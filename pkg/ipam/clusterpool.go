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

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s"

	"github.com/cilium/cilium/pkg/controller"

	"github.com/cilium/cilium/pkg/ipam/types"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/cilium/cilium/pkg/lock"

	"github.com/cilium/ipam/service/ipallocator"
)

// TODO make these either cilium-agent CLI flags or part of the CRD
const (
	depletionThreshold = 8  // per pool or globally?
	releaseThreshold   = 16 // globally
)

func newPodCIDRAllocator(podCIDR string) (*ipallocator.Range, error) {
	_, cidr, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid pod CIDR: %w", err)
	}

	return ipallocator.NewCIDRRange(cidr)
}

type podCIDRPool struct {
	mutex    lock.Mutex
	family   Family
	pool     map[string]*ipallocator.Range
	podCIDRs []string
	released map[string]struct{}
}

func newPodCIDRPool(family Family) *podCIDRPool {
	return &podCIDRPool{
		mutex:    lock.Mutex{},
		family:   family,
		pool:     map[string]*ipallocator.Range{},
		podCIDRs: []string{},
		released: map[string]struct{}{},
	}
}

func (p *podCIDRPool) allocate(ip net.IP) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, alloc := range p.pool {
		cidr := alloc.CIDR()
		if cidr.Contains(ip) {
			return alloc.Allocate(ip)
		}
	}

	return fmt.Errorf("IP %s not in range of any pod CIDR", ip)
}

func (p *podCIDRPool) allocateNext() (net.IP, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// When allocating a random IP, we try the pod CIDRs in the order they are
	// listed in the CRD. This avoids internal fragmentation.
	for _, cidr := range p.podCIDRs {
		if alloc := p.pool[cidr]; alloc != nil && alloc.Free() > 0 {
			return alloc.AllocateNext()
		}
	}

	return nil, errors.New("all pod CIDR ranges are exhausted")
}

func (p *podCIDRPool) release(ip net.IP) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, alloc := range p.pool {
		cidr := alloc.CIDR()
		if cidr.Contains(ip) {
			return alloc.Release(ip)
		}
	}

	return nil
}

func (p *podCIDRPool) hasAvailableIPs() bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, alloc := range p.pool {
		if alloc.Free() > 0 {
			return true
		}
	}

	return false
}

func (p *podCIDRPool) dump() (ipToOwner map[string]string, usedIPs, availableIPs, numPodCIDRs uint64, err error) {
	// TODO(gandro): Use the Snapshot interface to avoid locking during dump
	p.mutex.Lock()
	defer p.mutex.Unlock()

	ipToOwner = map[string]string{}
	for _, alloc := range p.pool {
		usedIPs += uint64(alloc.Used())
		availableIPs += uint64(alloc.Free())
		numPodCIDRs += 1

		alloc.ForEach(func(ip net.IP) {
			ipToOwner[ip.String()] = ""
		})
	}

	return ipToOwner, usedIPs, availableIPs, numPodCIDRs, nil
}

func (p *podCIDRPool) status() types.UsedPodCIDRMap {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	result := types.UsedPodCIDRMap{}

	totalAvailableIPs := uint64(0)
	unusedAllocators := map[string]*ipallocator.Range{}
	for cidr, alloc := range p.pool {
		status := types.PodCIDRStatusInUse
		if alloc.Free() <= depletionThreshold {
			status = types.PodCIDRStatusDepleted
		}

		totalAvailableIPs += uint64(alloc.Free())
		if alloc.Used() == 0 {
			unusedAllocators[cidr] = alloc
		}

		result[cidr] = types.UsedPodCIDR{
			Status: status,
		}
	}

	// check if unused allocated can be released
	for cidr, alloc := range unusedAllocators {
		availableIPs := uint64(alloc.Free())
		if totalAvailableIPs-availableIPs > releaseThreshold {
			log.WithField(logfields.CIDR, cidr).Debug("removing pod CIDR from allocation pool")

			totalAvailableIPs -= availableIPs
			p.released[cidr] = struct{}{}
			delete(p.pool, cidr)
		}
	}

	// update status for all released pod CIDRs
	for podCIDR := range p.released {
		result[podCIDR] = types.UsedPodCIDR{
			Status: types.PodCIDRStatusReleased,
		}
	}

	return result
}

func (p *podCIDRPool) updatePool(podCIDRs []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	podCIDRSet := map[string]struct{}{}
	for _, podCIDR := range podCIDRs {
		podCIDRSet[podCIDR] = struct{}{}

		if _, ok := p.released[podCIDR]; ok {
			continue // already released
		}

		if _, ok := p.pool[podCIDR]; ok {
			continue // already exists
		}

		log.WithField(logfields.CIDR, podCIDR).Debug("adding new pod CIDR to allocation pool")
		alloc, err := newPodCIDRAllocator(podCIDR)
		if err != nil {
			log.
				WithError(err).
				WithField(logfields.CIDR, podCIDR).
				Error("failed to add pod CIDR to allocation pool")
			continue
		}

		p.pool[podCIDR] = alloc
	}

	// we allocate from the pod CIDRs in the order they are listed here
	p.podCIDRs = podCIDRs

	// remove any released CIDRs no longer present in the CRD
	for cidr := range p.released {
		if _, ok := podCIDRSet[cidr]; !ok {
			delete(p.released, cidr)
		}
	}

	// sanity check: did pod CIDRs get removed without prior release
	for cidr := range p.pool {
		if _, ok := podCIDRSet[cidr]; !ok {
			log.
				WithField(logfields.CIDR, cidr).
				Error("pod CIDR was removed from CiliumNode CRD without the agent releasing it first." +
					"This will likely lead to IP conflicts if this CIDR is reused.")
			delete(p.pool, cidr)
		}
	}
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

type crdWatcher struct {
	mutex      lock.Mutex
	pools      map[Family]*podCIDRPool
	controller *controller.Manager

	node               *ciliumv2.CiliumNode
	previouslyReleased map[Family][]string
}

var crdWatcherInit sync.Once
var sharedCRDWatcher *crdWatcher

func newCRDWatcher(k8sEventReg K8sEventRegister) *crdWatcher {
	c := &crdWatcher{
		mutex:              lock.Mutex{},
		pools:              map[Family]*podCIDRPool{},
		controller:         controller.NewManager(),
		node:               nil,
		previouslyReleased: map[Family][]string{},
	}

	startLocalCiliumNodeInformer(nodeTypes.GetName(), k8sEventReg,
		c.localNodeUpdated, c.localNodeDeleted)

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
	_, err := k8s.CiliumClient().CiliumV2().CiliumNodes().
		UpdateStatus(ctx, node, metav1.UpdateOptions{})
	return err
}

type clusterPoolAllocator struct {
	pool *podCIDRPool
}

func newClusterPoolAllocator(family Family, k8sEventReg K8sEventRegister) Allocator {
	pool := newPodCIDRPool(family)

	crdWatcherInit.Do(func() {
		sharedCRDWatcher = newCRDWatcher(k8sEventReg)
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
