// +build hci_channel_raw

package linux

import (
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"syscall"
	"unsafe"

	"github.com/paypal/gatt/linux/gioctl"
	"github.com/paypal/gatt/linux/socket"
)

type device struct {
	fd   int
	dev  int
	name string
	rmu  *sync.Mutex
	wmu  *sync.Mutex
}

func newDevice(n int, chk bool) (*device, error) {
	d := hciOpenDev(socket.AF_BLUETOOTH)
	req := devListRequest{devNum: hciMaxDevices}
	if err := gioctl.Ioctl(uintptr(d.fd), hciGetDeviceList, uintptr(unsafe.Pointer(&req))); err != nil {
		log.Printf("linux.device_hci_raw_channel.newDevice error: %s", err)
		return nil, err
	}
	return d, nil
}

func newSocket(fd, n int, chk bool) (*device, error) {
	i := hciDevInfo{id: uint16(n)}
	if err := gioctl.Ioctl(uintptr(fd), hciGetDeviceInfo, uintptr(unsafe.Pointer(&i))); err != nil {
		return nil, err
	}
	name := string(i.name[:])
	// Check the feature list returned feature list.
	if chk && i.features[4]&0x40 == 0 {
		err := errors.New("does not support LE")
		log.Printf("dev: %s %s", name, err)
		return nil, err
	}
	log.Printf("dev: %s up", name)

	// Only bind with HCI_CHANNEL_RAW
	sa := socket.SockaddrHCI{Dev: n, Channel: socket.HCI_CHANNEL_RAW}
	if err := socket.Bind(fd, &sa); err != nil {
		log.Printf("dev: %s can't bind to hci raw channel, err: %s.", name, err)
		return nil, err
	}

	// disable scanning, it may have been left on, if so
	// hci_le_set_scan_parameters will fail without this
	hciLeSetScanEnable(fd, 0x00, 0, 1000)

	return &device{
		fd:   fd,
		dev:  n,
		name: name,
		rmu:  &sync.Mutex{},
		wmu:  &sync.Mutex{},
	}, nil
}

func (d device) Read(b []byte) (int, error) {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	return syscall.Read(d.fd, b)
}

func (d device) Write(b []byte) (int, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	return syscall.Write(d.fd, b)
}

func (d device) Close() error {
	return syscall.Close(d.fd)
}

// Bluez lib/hci.c

// HCI Events
const (
	EVT_CMD_STATUS    = 0x0F
	EVT_CMD_COMPLETE  = 0x0E
	EVT_LE_META_EVENT = 0x3E
)

// HCI Packet structures
const (
	HCI_COMMAND_HDR_SIZE = 3
)

// HCI Packet types
const (
	HCI_COMMAND_PKT = 0x01
	HCI_ACLDATA_PKT = 0x02
	HCI_SCODATA_PKT = 0x03
	HCI_EVENT_PKT   = 0x04
	HCI_VENDOR_PKT  = 0xff
)

// LE commands
const (
	OGF_LE_CTL                     = 0x08
	OCF_LE_SET_SCAN_ENABLE         = 0x000C
	OCF_LE_SET_SCAN_PARAMETERS     = 0x000B
	LE_SET_SCAN_PARAMETERS_CP_SIZE = 7
	LE_SET_SCAN_ENABLE_CP_SIZE     = 2
)

type HCIRequest struct {
	ogf    uint16
	ocf    uint16
	event  int
	cparam *LeCparameter
	clen   int
	rparam *uint8
	rlen   int
}

type HCICommandHdr struct {
	opcode uint16 // OCF & OGF
	plen   uint8
}

type BDAddress struct {
	b [6]uint8
}

type LeCparameter struct {
	iovec  syscall.Iovec
	bdaddr *BDAddress
}

func LeSetScanParametersCP(packet_type uint8, interval uint16, window uint16,
	own_bdaddr_type uint8, filter uint8) (cparam LeCparameter) {
	bs := make([]byte, 4)
	var bdaddr BDAddress
	cparam = LeCparameter{
		iovec:  syscall.Iovec{Base: &bs[0], Len: 0},
		bdaddr: &bdaddr,
	}
	return cparam
}

func LeSetScanEnableCP(enable uint8, filter_dup uint8) (cparam LeCparameter) {
	var bdaddr BDAddress
	bs := make([]byte, 4)
	cparam = LeCparameter{
		iovec:  syscall.Iovec{Base: &bs[0], Len: 0},
		bdaddr: &bdaddr,
	}
	return cparam
}

func writev(dd int, iovec []syscall.Iovec) (nw int, errno syscall.Errno) {
	nw_raw, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(dd),
		uintptr(unsafe.Pointer(&iovec[0])), uintptr(len(iovec)))
	nw = int(nw_raw)
	return
}

// [bluez/lib/hci.h]  cmd_opcode_pack()
func cmdOpcodePack(ogf uint16, ocf uint16) uint16 {
	return ((ocf & 0x03ff) | (ogf << 10))
}

// [bluez/lib/hci.c]  hci_for_each_dev()
func hciForEachDev() (*device, error) {
	fd, err := socket.Socket(socket.AF_BLUETOOTH, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, socket.BTPROTO_HCI)
	if err != nil {
		// on error
		return nil, err
	}
	req := devListRequest{devNum: hciMaxDevices}
	if err := gioctl.Ioctl(uintptr(fd), hciGetDeviceList, uintptr(unsafe.Pointer(&req))); err != nil {
		// cannot get device list
		return nil, err
	}
	for i := 0; i < int(req.devNum); i++ {
		d, err := newSocket(fd, i, true)
		if err == nil {
			log.Printf("dev: %s opened", d.name)
			return d, err
		}
	}
	return nil, errors.New("no supported devices available")
}

// [bluez/lib/hci.c]  hci_send_cmd()
func hciSendCmd(dd int, ogf uint16, ocf uint16, plen uint8, param syscall.Iovec) int {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, HCI_COMMAND_PKT)
	var hc HCICommandHdr
	var iovec syscall.Iovec
	var iv []syscall.Iovec

	// TODO: Consider the endianness.
	hc.opcode = cmdOpcodePack(ogf, ocf)
	hc.plen = plen
	hcByteArray := make([]byte, 4)
	binary.BigEndian.PutUint16(hcByteArray, hc.opcode)
	binary.BigEndian.PutUint16(hcByteArray, uint16(hc.plen))

	iovec = syscall.Iovec{Base: &bs[0], Len: 1}
	iv = append(iv, iovec)
	iovec = syscall.Iovec{Base: &hcByteArray[0], Len: HCI_COMMAND_HDR_SIZE}
	iv = append(iv, iovec)
	if plen > 1 {
		iv = append(iv, param)
	}

	_, errno := writev(dd, iv)
	for errno != 0 {
		if (errno != syscall.EAGAIN) && (errno != syscall.EINTR) {
			log.Printf("linux.device_hci_raw_channel.hciSendCmd failed (error: %s)", errno)
			return -1
		}
		log.Printf("linux.device_hci_raw_channel.hciSendCmd retry (error: %s)", errno)
		_, errno = writev(dd, iv)
	}
	return 0
}

// [bluez/lib/hci.c]  hci_send_req()
func hciSendReq(dd int, r *HCIRequest, to int) int {
	nf := socket.HCIFilter{
		TypeMask:  0x00,
		EventMask: 0x00,
	}

	opcode := cmdOpcodePack(0, 0)
	socket.HciFilterSetPtype(HCI_EVENT_PKT, &nf)
	socket.HciFilterSetEvent(EVT_CMD_STATUS, &nf)
	socket.HciFilterSetEvent(EVT_CMD_COMPLETE, &nf)
	socket.HciFilterSetEvent(EVT_LE_META_EVENT, &nf)
	socket.HciFilterSetEvent(uint64(r.event), &nf)
	socket.HciFilterSetOpcode(opcode, &nf)

	if err := socket.SetsockoptFilter(dd, &nf); err != nil {
		return -1
	}

	if hciSendCmd(dd, r.ogf, r.ocf, uint8(r.clen), r.cparam.iovec) < 0 {
		log.Fatalf("hciSendCmd Failed.")
	}

	return 0
}

// [bluez/lib/hci.c]  hci_le_set_scan_enable()
func hciLeSetScanEnable(fd int, enable uint8, filter_dup uint8, to int) int {
	cparam := LeSetScanEnableCP(enable, filter_dup)
	var status uint8

	rq := HCIRequest{
		ogf:    OGF_LE_CTL,
		ocf:    OCF_LE_SET_SCAN_PARAMETERS,
		event:  0,
		cparam: &cparam,
		clen:   LE_SET_SCAN_PARAMETERS_CP_SIZE,
		rparam: &status,
		rlen:   1,
	}

	if hciSendReq(fd, &rq, to) < 0 {
		return 0
	}
	return 0
}

// [bluez/lib/hci.c]  hci_le_set_scan_paramaters()
func hciLeSetScanParameters(dd int, packet_type uint8, interval uint16, window uint16,
	own_type uint8, filter uint8, to int) int {

	cparam := LeSetScanParametersCP(packet_type, interval, window, own_type, filter)

	var status uint8

	rq := HCIRequest{
		ogf:    OGF_LE_CTL,
		ocf:    OCF_LE_SET_SCAN_PARAMETERS,
		event:  0,
		cparam: &cparam,
		clen:   LE_SET_SCAN_PARAMETERS_CP_SIZE,
		rparam: &status,
		rlen:   1,
	}
	if hciSendReq(dd, &rq, to) < 0 {
		return -1
	}
	return 0
}

// [bluez/lib/hci.c]  hci_open_dev() (+ hci_get_route())
func hciOpenDev(dev_id int) *device {
	d, err := hciGetRoute()
	if err != nil {
		log.Printf("linux.device_hci_raw_channel.hciOpenDev err: %s", err)
		return nil
	}
	return d
}

// [bluez/lib/hci.c]  hci_get_route()
func hciGetRoute() (*device, error) {
	d, err := hciForEachDev()
	// todo: check bdaddr
	return d, err
}
