package main

import (
  "fmt"
  "math"
  "sort"
  "strconv"
  "strings"
)

const (
  beginIP uint32 = 0
  endIP uint32 = 4294967295
)

func main() {
	inputs := [...]string{"10.0.0.3", "10.0.0.5"}
	ips := make([]string, len(inputs))
	for i, ip := range inputs {
	  ips[i] = ip
    }
	fmt.Println(ips)
	// Above are the inputs for testing, can input multiple ip addresses.
	// Calculate excluded intervals.
	excludedIPRanges := excludeRange(ips)
	fmt.Println(excludedIPRanges)

	// Represent intervals in CIDR.
	var excludedCIDRs []string
	for _, interval := range excludedIPRanges {
	  excludedCIDRs = append(excludedCIDRs, rangeToCIDR(interval)...)
    }
    fmt.Println(len(excludedCIDRs))
    fmt.Println(excludedCIDRs)
}

func rangeToCIDR(ipRange []uint32) []string {
  var cidrs []string
  var mask []uint32
  mask = append(mask, uint32(0))
  for i := 32; i >= 0; i-- {
    mask = append(mask, mask[32-i] + 1 << i)
  }
  mask = mask[1:]
  for ipRange[0] >= ipRange[1] {
    maxSize := 32
    for maxSize > 0 {
      host := ipRange[0] & mask[maxSize-1]
      if host != ipRange[0] {
        break
      }
      maxSize--
    }

    overlap := math.Log(float64(ipRange[1]-ipRange[0])+1) / math.Log(2)
    maxDiff := 32 - int(math.Floor(overlap))
    if maxSize < maxDiff {
      maxSize = maxDiff
    }

    cidrs = append(cidrs, uint32ToIPv4(ipRange[0])+"/"+strconv.Itoa(maxSize))
    ipRange[0] += uint32(math.Exp2(float64(32 - maxSize)))
  }
  return cidrs
}

func excludeRange(ips []string) [][]uint32 {
  // Convert list of address strings to uint32
  var ipsInUint32[]uint32
  for _, ip := range ips {
    ipsInUint32 = append(ipsInUint32, ipToUint32(ip))
  }
  sort.Slice(ipsInUint32, func(i, j int) bool { return i < j })

  // Calculate the excluded ranges in uint32
  var excludedIPs [][]uint32
  // First interval
  if ipsInUint32[0] != beginIP {
    excludedIPs = append(excludedIPs, []uint32{beginIP, ipsInUint32[0]-1})
  }
  // All intermediate intervals
  for idx := 0; idx < len(ipsInUint32)-1; idx ++ {
    if ipsInUint32[idx] == ipsInUint32[idx+1]-1 {
      idx += 1
      continue
    }
    excludedIPs = append(excludedIPs, []uint32{ipsInUint32[idx]+1, ipsInUint32[idx+1]-1})
  }
  // Last interval
  if ipsInUint32[len(ipsInUint32)-1] != endIP {
    excludedIPs = append(excludedIPs, []uint32{ipsInUint32[len(ipsInUint32)-1]+1, endIP})
  }
  return excludedIPs
}

func ipToUint32(ip string) uint32 {
  // IP address string to one uint32 result
  // Splits into 4 sections
  ipSlices := strings.Split(ip, ".")
  result := uint32(0)
  for idx, ip := range ipSlices {
    ipInUint32, _ := strconv.ParseUint(ip, 10, 32)
    result |= uint32(ipInUint32) << (24 - idx*8)
  }
  return result
}

func uint32ToIPv4(ipInUint32 uint32) (ip string) {
  return fmt.Sprintf("%d.%d.%d.%d",
    ipInUint32>>24, (ipInUint32&0x00FFFFFF)>>16, (ipInUint32&0x0000FFFF)>>8, ipInUint32&0x000000FF)
}