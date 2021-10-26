package ipam

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/gomega"
)

type fakeK8sCiliumNodeAPI struct {
	mutex lock.Mutex
	node  *ciliumv2.CiliumNode

	onUpsert      func(*ciliumv2.CiliumNode)
	onUpsertEvent func()
	onDelete      func()
	onDeleteEvent func()
}

// subscribe implements localNodeInformer
func (f *fakeK8sCiliumNodeAPI) subscribe(_ K8sEventRegister, onUpsert func(*ciliumv2.CiliumNode), onDelete func()) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.onUpsert = onUpsert
	f.onDelete = onDelete
}

// UpdateStatus implements nodeUpdater
func (f *fakeK8sCiliumNodeAPI) UpdateStatus(_ context.Context, ciliumNode *ciliumv2.CiliumNode, _ v1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	f.updateNode(ciliumNode)
	return ciliumNode, nil
}

// updateNode is to be invoked by the test code to simulate writes by the operator
func (f *fakeK8sCiliumNodeAPI) updateNode(node *ciliumv2.CiliumNode) {
	f.mutex.Lock()
	onUpsert := f.onUpsert
	f.node = node
	onUpsertEvent := f.onUpsertEvent
	f.mutex.Unlock()

	if onUpsert != nil {
		onUpsert(node)
	}
	if onUpsertEvent != nil {
		onUpsertEvent()
	}
}

// updateNode is to be invoked by the test code to simulate an unexpected node deletion
func (f *fakeK8sCiliumNodeAPI) deleteNode() {
	f.mutex.Lock()
	onDelete := f.onDelete
	f.node = nil
	onDeleteEvent := f.onDeleteEvent
	f.mutex.Unlock()

	if onDelete != nil {
		onDelete()
	}
	if onDeleteEvent != nil {
		onDeleteEvent()
	}
}

func TestPodCIDRPool(t *testing.T) {
	for _, tc := range []struct {
		family       Family
		podCIDR      string
		capacity     int
		inRangeIP    net.IP
		outOfRangeIP net.IP
	}{
		{
			family:       IPv4,
			podCIDR:      "192.168.0.0/27",
			capacity:     30,
			inRangeIP:    net.ParseIP("192.168.0.1"),
			outOfRangeIP: net.ParseIP("10.0.0.1"),
		},
		{
			family:       IPv6,
			podCIDR:      "1::/123",
			capacity:     30,
			inRangeIP:    net.ParseIP("1::1"),
			outOfRangeIP: net.ParseIP("2::1"),
		},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			RegisterTestingT(t)

			p := newPodCIDRPool()

			// Test behavior when empty.
			ip, err := p.allocateNext()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeNil())
			ipToOwner, usedIPs, availableIPs, numPodCIDRs, err := p.dump()
			Expect(err).ToNot(HaveOccurred())
			Expect(ipToOwner).To(BeEmpty())
			Expect(usedIPs).To(BeZero())
			Expect(availableIPs).To(BeZero())
			Expect(numPodCIDRs).To(BeZero())
			Expect(p.hasAvailableIPs()).To(BeFalse())
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{}))

			// Add pod CIDRs.
			p.updatePool([]string{tc.podCIDR})
			Expect(p.hasAvailableIPs()).To(BeTrue())
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Test allocating a fixed IP.
			Expect(p.allocate(tc.inRangeIP)).To(Succeed())
			ipToOwner, usedIPs, availableIPs, numPodCIDRs, err = p.dump()
			Expect(err).ToNot(HaveOccurred())
			Expect(ipToOwner).To(Equal(map[string]string{
				tc.inRangeIP.String(): "",
			}))
			Expect(usedIPs).To(Equal(1))
			Expect(availableIPs).To(Equal(tc.capacity - 1))
			Expect(numPodCIDRs).To(Equal(1))
			Expect(p.release(tc.inRangeIP)).To(Succeed())

			// Test allocating an out-of-range IP.
			Expect(p.allocate(tc.outOfRangeIP)).ShouldNot(Succeed())
			Expect(p.release(tc.outOfRangeIP)).To(Succeed())

			// Test allocation of all IPs.
			ips := allocateNextN(p, tc.capacity, nil)

			// Test behavior when full.
			Expect(p.hasAvailableIPs()).To(BeFalse())
			ip, err = p.allocateNext()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeNil())
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR: {
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Test release of all IPs.
			for i, ip := range ips {
				Expect(p.release(ip)).To(Succeed())
				Expect(p.hasAvailableIPs()).To(BeTrue())
				expectedStatus := types.PodCIDRStatusInUse
				if i+1 < depletionThreshold {
					expectedStatus = types.PodCIDRStatusDepleted
				}
				Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
					tc.podCIDR: {
						Status: expectedStatus,
					},
				}))
			}

			// Test release of all pod CIDRs.
			p.updatePool(nil)
			ip, err = p.allocateNext()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeNil())
			Expect(p.hasAvailableIPs()).To(BeFalse())
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{}))
		})
	}
}

func TestPodCIDRPoolTwoPools(t *testing.T) {
	for _, tc := range []struct {
		family    Family
		podCIDR1  string
		capacity1 int
		podCIDR2  string
		capacity2 int
	}{
		{
			family:    IPv4,
			podCIDR1:  "192.168.0.0/27",
			capacity1: 30,
			podCIDR2:  "10.0.0.0/27",
			capacity2: 30,
		},
		{
			family:    IPv6,
			podCIDR1:  "1::/123",
			capacity1: 30,
			podCIDR2:  "2::/123",
			capacity2: 30,
		},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			RegisterTestingT(t)

			p := newPodCIDRPool()
			p.updatePool([]string{tc.podCIDR1})

			// Test behavior with no allocations.
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			_, podCIDR1, err := net.ParseCIDR(tc.podCIDR1)
			Expect(err).ToNot(HaveOccurred())
			_, podCIDR2, err := net.ParseCIDR(tc.podCIDR2)
			Expect(err).ToNot(HaveOccurred())

			// Test allocation and release of a single IP.
			ip, err := p.allocateNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(ip).ToNot(BeNil())
			Expect(podCIDR1.Contains(ip)).To(BeTrue())
			Expect(p.release(ip)).To(Succeed())

			// Test fully allocating the first pod CIDR.
			ips1 := allocateNextN(p, tc.capacity1, podCIDR1)
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Allocate the second pod CIDR.
			p.updatePool([]string{tc.podCIDR1, tc.podCIDR2})
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Test fully allocating the second pod CIDR.
			ips2 := allocateNextN(p, tc.capacity2, podCIDR2)
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Test that IP addresses are allocated from the first pod CIDR by
			// preference.
			Expect(p.release(ips1[0])).To(Succeed())
			Expect(p.release(ips2[0])).To(Succeed())
			ip, err = p.allocateNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(ip).To(Equal(ips1[0]))
			ip, err = p.allocateNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(ip).To(Equal(ips2[0]))

			// Test fully releasing the second pod CIDR.
			releaseAll(p, ips2)
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Test fully releasing the first pod CIDR.
			for i, ip := range ips1 {
				Expect(p.release(ip)).To(Succeed())

				ipToOwner, usedIPs, availableIPs, numPodCIDRs, err := p.dump()
				Expect(err).ToNot(HaveOccurred())
				Expect(ipToOwner).ToNot(BeNil())
				Expect(usedIPs).To(Equal(tc.capacity1 - i - 1))
				Expect(availableIPs).ToNot(BeZero())
				Expect(numPodCIDRs).To(Equal(2))

				var expectedStatus2 types.UsedPodCIDRStatus
				if i+1 < releaseThreshold {
					expectedStatus2 = types.PodCIDRStatusInUse
				} else {
					expectedStatus2 = types.PodCIDRStatusReleased
				}
				Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
					tc.podCIDR1: {
						Status: types.PodCIDRStatusInUse,
					},
					tc.podCIDR2: {
						Status: expectedStatus2,
					},
				}))
			}
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusInUse,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusReleased,
				},
			}))

			// Release the second pod CIDR.
			p.updatePool([]string{tc.podCIDR1})
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusInUse,
				},
			}))
		})
	}
}

func TestPodCIDRPoolRemoveInUse(t *testing.T) {
	for _, tc := range []struct {
		name           string
		family         Family
		podCIDRs       []string
		allocate       int
		afterPodCIDRs  []string
		expectedStatus types.UsedPodCIDRMap
	}{
		{
			name:   "remove_first_unused",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
			},
			expectedStatus: types.UsedPodCIDRMap{
				"192.168.0.0/27": {
					Status: types.PodCIDRStatusInUse,
				},
			},
		},
		{
			name:   "remove_first_in_use",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
			},
			allocate: 1,
			expectedStatus: types.UsedPodCIDRMap{
				"192.168.0.0/27": {
					Status: types.PodCIDRStatusInUse,
				},
			},
		},
		{
			name:   "remove_second_unused",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
				"192.168.1.0/27",
			},
			allocate: 1,
			afterPodCIDRs: []string{
				"192.168.0.0/27",
			},
			expectedStatus: types.UsedPodCIDRMap{
				"192.168.0.0/27": {
					Status: types.PodCIDRStatusInUse,
				},
			},
		},
		{
			name:   "remove_second_in_use",
			family: IPv4,
			podCIDRs: []string{
				"192.168.0.0/27",
				"192.168.1.0/27",
			},
			allocate: 31,
			afterPodCIDRs: []string{
				"192.168.0.0/27",
			},
			expectedStatus: types.UsedPodCIDRMap{
				"192.168.0.0/27": {
					Status: types.PodCIDRStatusDepleted,
				},
				"192.168.1.0/27": {
					Status: types.PodCIDRStatusInUse,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)

			p := newPodCIDRPool()
			p.updatePool(tc.podCIDRs)
			_ = allocateNextN(p, tc.allocate, nil)
			p.updatePool(tc.afterPodCIDRs)
			Expect(p.status()).To(Equal(tc.expectedStatus))
		})
	}
}

func TestNewCRDWatcher(t *testing.T) {
	for _, tc := range []struct {
		family    Family
		podCIDR1  string
		capacity1 int
		podCIDR2  string
		capacity2 int
	}{
		{
			family:    IPv4,
			podCIDR1:  "0.0.0.0/27",
			capacity1: 30,
			podCIDR2:  "1.0.0.0/27",
			capacity2: 30,
		},
		{
			family:    IPv6,
			podCIDR1:  "1::/123",
			capacity1: 30,
			podCIDR2:  "2::/123",
			capacity2: 30,
		},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			RegisterTestingT(t)

			fakeK8sEventRegister := &ownerMock{}
			events := make(chan string, 1)
			fakeK8sCiliumNodeAPI := &fakeK8sCiliumNodeAPI{
				onDeleteEvent: func() {
					events <- "delete"
				},
				onUpsertEvent: func() {
					events <- "upsert"
				},
			}

			// Test that the watcher updates the CiliumNode CRD.
			c := newCRDWatcher(fakeK8sEventRegister, fakeK8sCiliumNodeAPI, fakeK8sCiliumNodeAPI)
			c.setPodCIDRPool(tc.family, newPodCIDRPool())
			c.setPodCIDRPool(IPv6, newPodCIDRPool())
			c.localNodeUpdated(&ciliumv2.CiliumNode{
				Spec: ciliumv2.NodeSpec{
					IPAM: types.IPAMSpec{
						PodCIDRs: []string{
							tc.podCIDR1,
						},
					},
				},
			})
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.node).NotTo(BeNil())
			Expect(fakeK8sCiliumNodeAPI.node.Status.IPAM.UsedPodCIDRs).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: types.UsedPodCIDR{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Deplete all IPs in the first pod CIDR.
			ip1s := allocateNextN(c.pools[tc.family], tc.capacity1, nil)
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.node.Status.IPAM.UsedPodCIDRs).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: types.UsedPodCIDR{
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Allocate the second pod CIDR.
			c.localNodeUpdated(&ciliumv2.CiliumNode{
				Spec: ciliumv2.NodeSpec{
					IPAM: types.IPAMSpec{
						PodCIDRs: []string{
							tc.podCIDR1,
							tc.podCIDR2,
						},
					},
				},
			})
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.node.Status.IPAM.UsedPodCIDRs).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: types.UsedPodCIDR{
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: types.UsedPodCIDR{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Allocate all IPs in the second pod CIDR.
			ip2s := allocateNextN(c.pools[tc.family], tc.capacity2, nil)
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.node.Status.IPAM.UsedPodCIDRs).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: types.UsedPodCIDR{
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: types.UsedPodCIDR{
					Status: types.PodCIDRStatusDepleted,
				},
			}))

			// Release all IPs in the second pod CIDR.
			releaseAll(c.pools[tc.family], ip2s)
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.node.Status.IPAM.UsedPodCIDRs).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: types.UsedPodCIDR{
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: types.UsedPodCIDR{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Release all IPs in the first pod CIDR.
			releaseAll(c.pools[tc.family], ip1s)
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.node.Status.IPAM.UsedPodCIDRs).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: types.UsedPodCIDR{
					Status: types.PodCIDRStatusInUse,
				},
				tc.podCIDR2: types.UsedPodCIDR{
					Status: types.PodCIDRStatusReleased,
				},
			}))

			// Deallocate the second pod CIDR.
			c.localNodeUpdated(&ciliumv2.CiliumNode{
				Spec: ciliumv2.NodeSpec{
					IPAM: types.IPAMSpec{
						PodCIDRs: []string{
							tc.podCIDR1,
						},
					},
				},
			})
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("upsert"))
			Expect(fakeK8sCiliumNodeAPI.node.Status.IPAM.UsedPodCIDRs).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: types.UsedPodCIDR{
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Delete the node.
			fakeK8sCiliumNodeAPI.deleteNode()
			c.controller.TriggerController("sync-clusterpool-status")
			Expect(<-events).To(Equal("delete"))
			Expect(fakeK8sCiliumNodeAPI.node).To(BeNil())
		})
	}
}

// allocateNextN allocates the next n IPs from pool. If cidr is not nil then it
// expects that it will contain all allocated IPs.
func allocateNextN(p *podCIDRPool, n int, cidr *net.IPNet) []net.IP {
	ips := make([]net.IP, 0, n)
	for i := 0; i < n; i++ {
		ip, err := p.allocateNext()
		Expect(err).ToNot(HaveOccurred())
		Expect(ip).ToNot(BeNil())
		if cidr != nil {
			Expect(cidr.Contains(ip)).To(BeTrue())
		}
		ips = append(ips, ip)
	}
	return ips
}

// releaseAll releases ips from the pool. It expects that all releases succeed.
func releaseAll(p *podCIDRPool, ips []net.IP) {
	for _, ip := range ips {
		Expect(p.release(ip)).To(Succeed())
	}
}
