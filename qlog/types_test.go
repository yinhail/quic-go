package qlog

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Types", func() {
	It("has a string representation for the category", func() {
		Expect(categoryConnectivity.String()).To(Equal("connectivity"))
		Expect(categoryTransport.String()).To(Equal("transport"))
		Expect(categoryRecovery.String()).To(Equal("recovery"))
		Expect(categorySecurity.String()).To(Equal("security"))
	})

	It("has a string representation for the packet type", func() {
		Expect(PacketTypeInitial.String()).To(Equal("initial"))
		Expect(PacketTypeHandshake.String()).To(Equal("handshake"))
		Expect(PacketType0RTT.String()).To(Equal("0RTT"))
		Expect(PacketType1RTT.String()).To(Equal("1RTT"))
		Expect(PacketTypeRetry.String()).To(Equal("retry"))
		Expect(PacketTypeVersionNegotiation.String()).To(Equal("version_negotiation"))
	})
})
