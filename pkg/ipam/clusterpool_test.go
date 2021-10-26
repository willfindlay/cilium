package ipam

import (
	"context"
	"net"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/lock"

	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	. "github.com/onsi/gomega"
)

type fakeK8sCiliumNodeAPI struct {
	mutex lock.Mutex
	node  *ciliumv2.CiliumNode

	onUpsert func(*ciliumv2.CiliumNode)
	onDelete func()
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
	f.mutex.Unlock()

	if onUpsert != nil {
		onUpsert(node)
	}
}

// updateNode is to be invoked by the test code to simulate an unexpected node deletion
func (f *fakeK8sCiliumNodeAPI) deleteNode() {
	f.mutex.Lock()
	onDelete := f.onDelete
	f.node = nil
	f.mutex.Unlock()

	if onDelete != nil {
		onDelete()
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

			p := newPodCIDRPool(tc.family)

			// Test behavior when empty.
			ip, err := p.allocateNext()
			Expect(err).To(HaveOccurred())
			Expect(ip).To(BeNil())
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
			ipToOwner, usedIPs, availableIPs, numPodCIDRs, err := p.dump()
			Expect(err).ToNot(HaveOccurred())
			Expect(ipToOwner).To(Equal(map[string]string{
				tc.inRangeIP.String(): "",
			}))
			Expect(usedIPs).To(Equal(uint64(1)))
			Expect(availableIPs).To(Equal(uint64(tc.capacity - 1)))
			Expect(numPodCIDRs).To(Equal(uint64(1)))
			Expect(p.release(tc.inRangeIP)).To(Succeed())

			// Test allocating an out-of-range IP.
			Expect(p.allocate(tc.outOfRangeIP)).ShouldNot(Succeed())
			Expect(p.release(tc.outOfRangeIP)).To(Succeed())

			// Test allocation of all IPs.
			ips := make([]net.IP, 0, tc.capacity)
			for i := 0; i < tc.capacity; i++ {
				ip, err := p.allocateNext()
				Expect(err).ToNot(HaveOccurred())
				Expect(ip).ToNot(BeNil())
				ips = append(ips, ip)
			}

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
				if i < depletionThreshold {
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

func TestPodCIDRPoolMultiplePools(t *testing.T) {
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
			podCIDR1:  "1::/124",
			capacity1: 14,
			podCIDR2:  "2::/124",
			capacity2: 14,
		},
	} {
		t.Run(string(tc.family), func(t *testing.T) {
			RegisterTestingT(t)

			p := newPodCIDRPool(tc.family)
			p.updatePool([]string{tc.podCIDR1, tc.podCIDR2})

			// Test behavior with no allocations.
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusInUse,
				},
				tc.podCIDR2: {
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
			ips1 := make([]net.IP, 0, tc.capacity1)
			for i := 0; i < tc.capacity1; i++ {
				ip, err := p.allocateNext()
				Expect(err).ToNot(HaveOccurred())
				Expect(ip).ToNot(BeNil())
				Expect(podCIDR1.Contains(ip)).To(BeTrue())
				ips1 = append(ips1, ip)
			}
			Expect(p.status()).To(Equal(types.UsedPodCIDRMap{
				tc.podCIDR1: {
					Status: types.PodCIDRStatusDepleted,
				},
				tc.podCIDR2: {
					Status: types.PodCIDRStatusInUse,
				},
			}))

			// Test fully allocating the second pod CIDR.
			ips2 := make([]net.IP, 0, tc.capacity1)
			for i := 0; i < tc.capacity2; i++ {
				ip, err := p.allocateNext()
				Expect(err).ToNot(HaveOccurred())
				Expect(ip).ToNot(BeNil())
				Expect(podCIDR2.Contains(ip)).To(BeTrue())
				ips2 = append(ips2, ip)
			}
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
			for _, ip := range ips2 {
				Expect(p.release(ip)).To(Succeed())
			}
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
				var expectedStatus2 types.UsedPodCIDRStatus
				switch {
				case i < releaseThreshold:
					expectedStatus2 = types.PodCIDRStatusReleased
				case i < depletionThreshold:
					expectedStatus2 = types.PodCIDRStatusDepleted
				default:
					expectedStatus2 = types.PodCIDRStatusInUse
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
		})
	}
}

func TestNewCRDWatcher(t *testing.T) {
	RegisterTestingT(t)

	Expect(func() {
		mockNodeAPI := &fakeK8sCiliumNodeAPI{}
		_ = newCRDWatcher(&ownerMock{}, mockNodeAPI, mockNodeAPI)
	}).NotTo(Panic())
}
