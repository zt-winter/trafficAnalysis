package tool

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

//将源IP与目的IP结合，A发送给B，B发送给A归为一类
func CombineIP(src string, dst string) []byte {
	addressA := []byte(src)
	addressB := []byte(dst)
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
	newAddress := make([]byte, 0)
	if flag {
		newAddress = append(newAddress, addressA...)
		newAddress = append(newAddress, addressB...)
	} else {
		newAddress = append(newAddress, addressB...)
		newAddress = append(newAddress, addressA...)
	}
	return newAddress
}

func CombineIPPort(src string, addressAPort string, dst string, addressBPort string) []byte {
	addressA := []byte(src)
	addressB := []byte(dst)
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
				break
			} else if i == lengthB - 1 {
				flag = false
				break
			}
		}
	}
	newAddress := make([]byte, 0)
	if flag {
		newAddress = append(newAddress, addressA...)
		newAddress = append(newAddress, []byte(addressAPort)...)
		newAddress = append(newAddress, addressB...)
		newAddress = append(newAddress, []byte(addressBPort)...)
	} else {
		newAddress = append(newAddress, addressB...)
		newAddress = append(newAddress, []byte(addressBPort)...)
		newAddress = append(newAddress, addressA...)
		newAddress = append(newAddress, []byte(addressAPort)...)
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

func Uint16ToBytes(port uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return buf
}

func NetBytesToUint(data []byte, length int) (uint, error) {
	if length == 3 {
		data = append([]byte{0}, data...)
	}
	bytesBuffer := bytes.NewBuffer(data)
	switch length {
	case 1:
		var tmp uint8
		err := binary.Read(bytesBuffer, binary.BigEndian, &tmp)
		return uint(tmp), err
	case 2:
		var tmp uint16
		err := binary.Read(bytesBuffer, binary.BigEndian, &tmp)
		return uint(tmp), err
	case 3, 4:
		var tmp uint32
		err := binary.Read(bytesBuffer, binary.BigEndian, &tmp)
		return uint(tmp), err
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

func IntToUint(a int) uint {
	var one uint = 1;
	var b int = 1;
	var ret uint = 0;
	var i int = 0;
	for i = 0; i < 32; i++ {
		if a & b > 0 {
			ret += one;
		}
		b = b << 1;
		one = one << 1;
	}
	return ret
}
