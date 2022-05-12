package tool

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

//将源IP与目的IP结合，A发送给B，B发送给A归为一类
func CombineIP(addressA net.IP, addressB net.IP) []byte {
	lengthA := len(addressA)
	lengthB := len(addressB)
	var flag bool
	for i := 0; i < lengthA && i < lengthB; i++ {
		if addressA[i] < addressB[i] {
			flag = true
			break
		} else if addressA[i] > addressB[i] {
			flag = false
			break
		} else {
			if i == lengthA - 1 {
				flag = true
			} else if i == lengthB - 1 {
				flag = false
			}
		}
	}
	var newAddress []byte
	if flag {
		newAddress = append(addressA, addressB...)
	} else {
		newAddress = append(addressB, addressA...)
	}
	return newAddress
}

func CombineIPPort(addressA net.IP, addressAPort uint16, addressB net.IP, addressBPort uint16) []byte {
	lengthA := len(addressA)
	lengthB := len(addressB)
	var flag bool
	for i := 0; i < lengthA && i < lengthB; i++ {
		if addressA[i] < addressB[i] {
			flag = true
			break
		} else if addressA[i] > addressB[i] {
			flag = false
			break
		} else {
			if i == lengthA - 1 {
				flag = true
			} else if i == lengthB - 1 {
				flag = false
			}
		}
	}
	var newAddress []byte
	if flag {
		newAddress = append(addressA, uint16ToBytes(addressAPort)...)
		newAddress = append(newAddress, addressB...)
		newAddress = append(newAddress, uint16ToBytes(addressBPort)...)
	} else {
		newAddress = append(addressB, uint16ToBytes(addressBPort)...)
		newAddress = append(newAddress, addressA...)
		newAddress = append(newAddress, uint16ToBytes(addressAPort)...)
	}
	return newAddress
}

//在map查询是否有相关IP结合
func SearchAddress(address []byte, mapAddress map[string]int) int {
	stringAddress := string(address)
	value, ok := mapAddress[stringAddress]
	if ok {
		return value
	} else {
		return -1
	}
}

func uint16ToBytes(port uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return buf
}

func NetBytesToInt(data []byte, length int) (int, error) {
	if length == 3 {
		data = append([]byte{0}, data...)
	}
	bytesBuffer := bytes.NewBuffer(data)
	switch length {
	case 1:
		var tmp int8
		err := binary.Read(bytesBuffer, binary.BigEndian, &tmp)
		return int(tmp), err
	case 2:
		var tmp int16
		err := binary.Read(bytesBuffer, binary.BigEndian, &tmp)
		return int(tmp), err
	case 3, 4:
		var tmp int32
		err := binary.Read(bytesBuffer, binary.BigEndian, &tmp)
		return int(tmp), err
	default:
		return 0, fmt.Errorf("%s", "bytes len is invaild")
	}
}

func NetByteToString(data []byte, length int) (string, error) {
	tmp := make([]byte, len(data))
	bytesBuffer := bytes.NewBuffer(data)
	err := binary.Read(bytesBuffer, binary.BigEndian, tmp)
	fmt.Println(string(tmp))
	return string(tmp), err
}
