// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/ipam/service/ipallocator"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO make these either cilium-agent CLI flags or part of the CRD
const (
	depletionThreshold = 8  // per pool or globally?
	releaseThreshold   = 16 // globally
)

// A podCIDRPool manages the allocation of IPs in multiple pod CIDRs.
type podCIDRPool struct {
	mutex        lock.Mutex
	ipAllocators []*ipallocator.Range
	released     map[string]struct{}
}

func newPodCIDRPool() *podCIDRPool {
	return &podCIDRPool{
		released: map[string]struct{}{},
	}
}

func (p *podCIDRPool) allocate(ip net.IP) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		if cidrNet.Contains(ip) {
			return ipAllocator.Allocate(ip)
		}
	}

	return fmt.Errorf("IP %s not in range of any pod CIDR", ip)
}

func (p *podCIDRPool) allocateNext() (net.IP, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// When allocating a random IP, we try the pod CIDRs in the order they are
	// listed in the CRD. This avoids internal fragmentation.
	for _, ipAllocator := range p.ipAllocators {
		if ipAllocator.Free() == 0 {
			continue
		}
		return ipAllocator.AllocateNext()
	}

	return nil, errors.New("all pod CIDR ranges are exhausted")
}

func (p *podCIDRPool) release(ip net.IP) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		if cidrNet.Contains(ip) {
			return ipAllocator.Release(ip)
		}
	}

	return nil
}

func (p *podCIDRPool) hasAvailableIPs() bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		if ipAllocator.Free() > 0 {
			return true
		}
	}

	return false
}

func (p *podCIDRPool) dump() (ipToOwner map[string]string, usedIPs, freeIPs, numPodCIDRs int, err error) {
	// TODO(gandro): Use the Snapshot interface to avoid locking during dump
	p.mutex.Lock()
	defer p.mutex.Unlock()

	ipToOwner = map[string]string{}
	for _, ipAllocator := range p.ipAllocators {
		usedIPs += ipAllocator.Used()
		freeIPs += ipAllocator.Free()
		ipAllocator.ForEach(func(ip net.IP) {
			ipToOwner[ip.String()] = ""
		})
	}
	numPodCIDRs = len(p.ipAllocators)

	return
}

func (p *podCIDRPool) free() int {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	free := 0
	for _, ipAllocator := range p.ipAllocators {
		free += ipAllocator.Free()
	}

	return free
}

func (p *podCIDRPool) status() types.UsedPodCIDRMap {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	result := types.UsedPodCIDRMap{}

	// Mark all released pod CIDRs as released.
	for cidrStr := range p.released {
		result[cidrStr] = types.UsedPodCIDR{
			Status: types.PodCIDRStatusReleased,
		}
	}

	// Compute the total number of free and used IPs for all non-released pod
	// CIDRs.
	totalFree := 0
	totalUsed := 0
	for _, r := range p.ipAllocators {
		cidrNet := r.CIDR()
		if _, released := p.released[cidrNet.String()]; released {
			continue
		}
		totalFree += r.Free()
		totalUsed += r.Used()
	}

	if totalFree < depletionThreshold {
		// If the total number of free IPs is below the depletion threshold,
		// then mark all pod CIDRs as depleted, unless they have already been
		// released.
		for _, ipAllocator := range p.ipAllocators {
			cidrNet := ipAllocator.CIDR()
			cidrStr := cidrNet.String()
			if _, released := p.released[cidrStr]; released {
				continue
			}
			result[cidrStr] = types.UsedPodCIDR{
				Status: types.PodCIDRStatusDepleted,
			}
		}
	} else {
		// Iterate over pod CIDRs in reverse order so we prioritize releasing
		// later pod CIDRs.
		for i := len(p.ipAllocators) - 1; i >= 0; i-- {
			ipAllocator := p.ipAllocators[i]
			cidrNet := ipAllocator.CIDR()
			cidrStr := cidrNet.String()
			if _, released := p.released[cidrStr]; released {
				continue
			}
			free := ipAllocator.Free()
			_ = free
			var status types.UsedPodCIDRStatus
			if i == 0 || ipAllocator.Used() > 0 {
				// If this is the first pod CIDR or it is used, then mark it as
				// in-use or depleted.
				if ipAllocator.Free() == 0 {
					status = types.PodCIDRStatusDepleted
				} else {
					status = types.PodCIDRStatusInUse
				}
			} else if free := ipAllocator.Free(); totalFree-free >= releaseThreshold {
				// Otherwise, if the pod CIDR is not used and releasing it would
				// not take us below the release threshold, then release it and
				// mark it as released.
				p.released[cidrStr] = struct{}{}
				totalFree -= free
				status = types.PodCIDRStatusReleased
				log.WithField(logfields.CIDR, cidrStr).Debug("releasing pod CIDR")
			} else {
				// Otherwise, mark the pod CIDR as in-use.
				status = types.PodCIDRStatusInUse
			}
			result[cidrStr] = types.UsedPodCIDR{
				Status: status,
			}
		}
	}

	return result
}

func (p *podCIDRPool) updatePool(podCIDRs []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// FIXME check for duplicates in podCIDRs

	// Special case: the first call to updatePool() with at least one valid pod
	// CIDR will create the initial allocators. The first pod CIDR is treated as
	// a special case and will never be released.
	if len(p.ipAllocators) == 0 {
		if len(podCIDRs) == 0 {
			log.Error("no pod CIDRs")
			return
		}

		ipAllocators := make([]*ipallocator.Range, 0, len(podCIDRs))
		for _, cidrStr := range podCIDRs {
			_, cidrNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				log.WithError(err).WithField(logfields.CIDR, cidrStr).Error("ignoring invalid pod CIDR")
				continue
			}
			ipAllocator, err := ipallocator.NewCIDRRange(cidrNet)
			if err != nil {
				log.WithError(err).WithField(logfields.CIDR, cidrStr).Error("cannot create *ipallocator.Range")
				continue
			}
			ipAllocators = append(ipAllocators, ipAllocator)
		}

		if len(ipAllocators) == 0 {
			log.Error("no valid pod CIDRs")
			return
		}

		p.ipAllocators = ipAllocators
		return
	}

	// Ignore invalid CIDRs.
	cidrNets := make([]*net.IPNet, 0, len(podCIDRs))
	cidrStrSet := make(map[string]struct{}, len(podCIDRs))
	for _, podCIDR := range podCIDRs {
		_, cidr, err := net.ParseCIDR(podCIDR)
		if err != nil {
			log.WithError(err).WithField(logfields.CIDR, podCIDR).Error("ignoring invalid pod CIDR")
			continue
		}
		cidrNets = append(cidrNets, cidr)
		cidrStrSet[cidr.String()] = struct{}{}
	}

	firstCIDRNet := p.ipAllocators[0].CIDR()
	if _, ok := cidrStrSet[firstCIDRNet.String()]; !ok {
		log.WithField(logfields.CIDR, firstCIDRNet.String()).Error("first pod CIDR was removed by operator")
	}

	// Remove any released pod CIDRs no longer present in the CRD.
	for cidrStr := range p.released {
		if _, ok := cidrStrSet[cidrStr]; !ok {
			delete(p.released, cidrStr)
		}
	}

	// newIPAllocators is the new slice of IP allocators.
	newIPAllocators := make([]*ipallocator.Range, 0, len(podCIDRs))

	// addedCIDRs is the set of pod CIDRs that have been added to newIPAllocators.
	addedCIDRs := make(map[string]struct{}, len(p.ipAllocators))

	// Add existing IP allocators to newIPAllocators in order.
	for i, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, ok := cidrStrSet[cidrStr]; !ok {
			if i != 0 && ipAllocator.Used() == 0 {
				continue
			}
			log.WithField(logfields.CIDR, cidrStr).Error("in-use pod CIDR was removed by operator")
		}
		newIPAllocators = append(newIPAllocators, ipAllocator)
		addedCIDRs[cidrStr] = struct{}{}
	}

	// Create and add new IP allocators to newIPAllocators.
	for _, cidrNet := range cidrNets {
		cidrStr := cidrNet.String()
		if _, ok := addedCIDRs[cidrStr]; ok {
			continue
		}
		ipAllocator, err := ipallocator.NewCIDRRange(cidrNet)
		if err != nil {
			log.WithError(err).WithField(logfields.CIDR, cidrStr).Error("cannot create *ipallocator.Range")
			continue
		}
		newIPAllocators = append(newIPAllocators, ipAllocator)
		addedCIDRs[cidrStr] = struct{}{} // Protect against duplicate CIDRs.
	}

	p.ipAllocators = newIPAllocators
}

func (p *podCIDRPool) markReleased(releasedCIDRs []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, cidr := range releasedCIDRs {
		p.released[cidr] = struct{}{}
	}
}

func podCIDRFamily(podCIDR string) Family {
	if strings.Contains(podCIDR, ":") {
		return IPv6
	}
	return IPv4
}

type localNodeInformer interface {
	subscribe(k8sEventReg K8sEventRegister, onUpsert func(*ciliumv2.CiliumNode), onDelete func())
}

type defaultNodeInformer struct{}

func (d *defaultNodeInformer) subscribe(k8sEventReg K8sEventRegister, onUpsert func(*ciliumv2.CiliumNode), onDelete func()) {
	startLocalCiliumNodeInformer(nodeTypes.GetName(), k8sEventReg,
		onUpsert, onDelete)
}

type nodeUpdater interface {
	UpdateStatus(ctx context.Context, ciliumNode *ciliumv2.CiliumNode, opts metav1.UpdateOptions) (*ciliumv2.CiliumNode, error)
}

type crdWatcher struct {
	mutex       lock.Mutex
	pools       map[Family]*podCIDRPool
	controller  *controller.Manager
	nodeUpdater nodeUpdater

	node               *ciliumv2.CiliumNode
	previouslyReleased map[Family][]string
}

var crdWatcherInit sync.Once
var sharedCRDWatcher *crdWatcher

func newCRDWatcher(k8sEventReg K8sEventRegister, localNodeInformer localNodeInformer, nodeUpdater nodeUpdater) *crdWatcher {
	c := &crdWatcher{
		mutex:              lock.Mutex{},
		pools:              map[Family]*podCIDRPool{},
		controller:         controller.NewManager(),
		nodeUpdater:        nodeUpdater,
		node:               nil,
		previouslyReleased: map[Family][]string{},
	}

	localNodeInformer.subscribe(k8sEventReg, c.localNodeUpdated, c.localNodeDeleted)

	c.controller.UpdateController("sync-clusterpool-status", controller.ControllerParams{
		DoFunc:      c.updateCiliumNodeStatus,
		RunInterval: 15 * time.Second,
	})

	return c
}

func (c *crdWatcher) setPodCIDRPool(family Family, pool *podCIDRPool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pools[family] = pool

	c.maintainPoolsLocked()
}

func (c *crdWatcher) maintainPoolsLocked() {
	if c.node == nil {
		return
	}

	// if we restored already released CIDRs make sure they are not used
	// FIXME(twpayne) is this needed?
	if len(c.previouslyReleased) > 0 {
		for family, releasedCIDRs := range c.previouslyReleased {
			if pool, ok := c.pools[family]; ok {
				pool.markReleased(releasedCIDRs)
				delete(c.previouslyReleased, family)
			}
		}
	}

	// updatePool requires that the order of pod CIDRs is maintained
	podCIDRsByFamily := map[Family][]string{}
	for _, podCIDR := range c.node.Spec.IPAM.PodCIDRs {
		family := podCIDRFamily(podCIDR)
		podCIDRsByFamily[family] = append(podCIDRsByFamily[family], podCIDR)
	}

	for family, podCIDRs := range podCIDRsByFamily {
		if pool, ok := c.pools[family]; ok {
			pool.updatePool(podCIDRs)
		}
	}
}

func (c *crdWatcher) localNodeUpdated(newNode *ciliumv2.CiliumNode) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// carry over released CIDRs from previous CRD to avoid accidental re-use
	if c.node == nil {
		for podCIDR, s := range newNode.Status.IPAM.UsedPodCIDRs {
			if s.Status == types.PodCIDRStatusReleased {
				family := podCIDRFamily(podCIDR)
				c.previouslyReleased[family] = append(c.previouslyReleased[family], podCIDR)
			}
		}
	}

	c.node = newNode
	c.maintainPoolsLocked()
}

func (c *crdWatcher) localNodeDeleted() {
	c.mutex.Lock()
	c.node = nil
	c.mutex.Unlock()
}

func (c *crdWatcher) updateCiliumNodeStatus(ctx context.Context) error {
	c.mutex.Lock()
	node := c.node.DeepCopy()
	c.mutex.Unlock()

	if node == nil {
		return nil // waiting on localNodeUpdated to be invoked first
	}

	oldStatus := node.Status.IPAM.DeepCopy()
	node.Status.IPAM.UsedPodCIDRs = types.UsedPodCIDRMap{}
	for _, pool := range c.pools {
		for podCIDR, status := range pool.status() {
			node.Status.IPAM.UsedPodCIDRs[podCIDR] = status
		}
	}

	if oldStatus.DeepEqual(&node.Status.IPAM) {
		return nil // no need to update
	}

	log.WithField("status", node.Status.IPAM.UsedPodCIDRs).Info("update status")
	_, err := c.nodeUpdater.UpdateStatus(ctx, node, metav1.UpdateOptions{})
	return err
}

type clusterPoolAllocator struct {
	pool *podCIDRPool
}

func newClusterPoolAllocator(family Family, k8sEventReg K8sEventRegister) Allocator {
	pool := newPodCIDRPool()

	crdWatcherInit.Do(func() {
		nodeClient := k8s.CiliumClient().CiliumV2().CiliumNodes()
		nodeInformer := &defaultNodeInformer{}
		sharedCRDWatcher = newCRDWatcher(k8sEventReg, nodeInformer, nodeClient)
	})
	sharedCRDWatcher.setPodCIDRPool(family, pool)

	for !pool.hasAvailableIPs() {
		log.WithFields(logrus.Fields{
			logfields.HelpMessage: "Check if cilium-operator pod is running and does not have any warnings or error messages.",
			logfields.Family:      family,
		}).Info("Waiting for pod CIDR to become available")
		time.Sleep(5 * time.Second)
	}

	return &clusterPoolAllocator{
		pool: pool,
	}
}

func (c *clusterPoolAllocator) Allocate(ip net.IP, owner string) (*AllocationResult, error) {
	return c.AllocateWithoutSyncUpstream(ip, owner)
}

func (c *clusterPoolAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string) (*AllocationResult, error) {
	if err := c.pool.allocate(ip); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolAllocator) AllocateNext(owner string) (*AllocationResult, error) {
	return c.AllocateNextWithoutSyncUpstream(owner)
}

func (c *clusterPoolAllocator) AllocateNextWithoutSyncUpstream(owner string) (*AllocationResult, error) {
	ip, err := c.pool.allocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolAllocator) Release(ip net.IP) error {
	return c.pool.release(ip)
}

func (c *clusterPoolAllocator) Dump() (map[string]string, string) {
	ipToOwner, usedIPs, availableIPs, numPodCIDRs, err := c.pool.dump()
	if err != nil {
		return nil, fmt.Sprintf("error: %s", err)
	}

	return ipToOwner, fmt.Sprintf("%d/%d allocated from %d pod CIDRs", usedIPs, availableIPs, numPodCIDRs)
}

func (c *clusterPoolAllocator) RestoreFinished() {
	// nothing to do
}
