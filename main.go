package main

import(
	"trafficAnalysis/extract"
)

type config struct {
	readPcapFile string
	filter string
	writeFeatureFloder string
}
	

func main() {
	var pcapname string = "/home/zt/data/3.9/3.9-miner.arch-miner.proxy.clash-xmrig-XMR.pcapng"
	var filter string = "tcp"
	extract.ExtractFeature(pcapname, filter)
	//包长累计变化图
	/*
	bar := charts.NewBar()
	bar.SetGlobalOptions(charts.WithTitleOpts(opts.Title{
		Title:		"包长分布图",
	}))
	bar.SetXAxis([]string{"0~50", "50~100", "100~150", "150~200", "200~250", "250~300", "300~350", "350~400", "400~450", "450~500"," <500"}).
		AddSeries("SSH-(aes-gcm-256)-xmr", generateItem(features))
	f, _ := os.Create("bar.html")
	bar.Render(f)
	*/
	//包长分布图
		
}

/*
func generateItem(features []Feature) []opts.BarData {
	items := make([]opts.BarData, 0)
	nums := make([]int, 11)
	for i := 0; i < 11; i++ {
		nums[i] = 0
	}
	var length int
	for i := 0; i < 1000; i++ {
		length = features[i].lenPacket
		switch {
			case length <= 50:
				nums[0] = nums[0] + 1
			case length > 50 && length <= 100:
				nums[1] = nums[1] + 1
			case length > 100 && length <= 150:
				nums[2] = nums[2] + 1
			case length > 150 && length <= 200:
				nums[3] = nums[3] + 1
			case length > 200 && length <= 250:
				nums[4] = nums[4] + 1
			case length > 250 && length <= 300:
				nums[5] = nums[5] + 1
			case length > 300 && length <= 350:
				nums[6] = nums[6] + 1
			case length > 350 && length <= 400:
				nums[7] = nums[7] + 1
			case length > 400 && length <= 450:
				nums[8] = nums[8] + 1
			case length > 450 && length <= 500:
				nums[9] = nums[9] + 1
			case length > 500:
				nums[10] = nums[10] + 1
			default:
		}
	}
	for i := 0; i < 11; i++ {
		items = append(items, opts.BarData{Value: nums[i]})
	}
	return items
}
*/
