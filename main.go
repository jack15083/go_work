package main

import (
	"bytes"
	"container/list"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ddliu/go-httpclient"
	"io"
	"io/ioutil"
	"math"
	"reflect"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type MyStr1 struct {
}

func (y *MyStr1) Test1() {
	fmt.Println("Test1 called")
}

type MyStr2 struct {
}

func (y *MyStr2) Test2(i int, oo string) {
	fmt.Println("Test2 called", i, oo)
}

func DynamicInvoke(object interface{}, methodName string, args ...interface{}) {
	inputs := make([]reflect.Value, len(args))
	for i, _ := range args {
		inputs[i] = reflect.ValueOf(args[i])
	}
	//动态调用方法
	reflect.ValueOf(object).MethodByName(methodName).Call(inputs)

	//动态访问属性
	reflect.ValueOf(object).Elem().FieldByName("Name")
}

func run(taskId int, taskChan chan int) {
	taskChan <- taskId

	go func() {
		time.Sleep(time.Second * time.Duration(3))
		log.Debug(fmt.Sprintf("执行task:%d", taskId))
		<-taskChan
	}()
}

func testRequest() {
	http := httpclient.NewHttpClient()
	res, err := http.PostJson("http://127.0.0.1:8000/invoke",
		`{"service_name":"demo.ExportProvider.GetExportTplByTplName", "param":{"tplName":"order"}, "client_id":"1"}`)

	if err != nil {
		fmt.Println(err)
		return
	}

	defer res.Body.Close()

	bodyByte, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(bodyByte))
}

type Handler interface {
	Do(k, v interface{})
}

type HandlerFunc func(k, v interface{})

func (hf HandlerFunc) Do(k, v interface{}) {
	hf(k, v)
}

func Each(mp map[interface{}]interface{}, h Handler) {
	if mp != nil && len(mp) > 0 {
		for k, v := range mp {
			h.Do(k, v)
		}
	}
}

func EachFunc(mp map[interface{}]interface{}, handlerFunc HandlerFunc) {
	if mp != nil && len(mp) > 0 {
		for k, v := range mp {
			handlerFunc(k, v)
		}
	}
}

func selfInfo(k, v interface{}) {
	fmt.Printf("my name is %s, i am %d years old", k, v)
	fmt.Println()
}

var wg sync.WaitGroup

type Duck interface {
	Quack()
}

type Cat struct {
	title string
}

func (c *Cat) Quack() {
	c.title = "test1"
	fmt.Println(c.title)
}

func (c *Cat) Test() {
	fmt.Println(c.title)
}

type TestStruct struct{}

func NilOrNot(v interface{}) bool {
	switch v.(type) {
	case *TestStruct:
		fmt.Println("this is test struct")
	}

	return v == nil
}

func handle(ctx context.Context, duration time.Duration) {
	select {
	case <-ctx.Done():
		fmt.Println("handle", ctx.Err())
	case <-time.After(duration):
		fmt.Println("process request with", duration)
	}
}

func WaitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	ch := make(chan bool, 1)

	go time.AfterFunc(timeout, func() {
		fmt.Println("timeout !")
		ch <- true
	})

	go func() {
		wg.Wait()
		fmt.Println("no timeout")
		ch <- false
	}()

	return <-ch
}

const (
	a = iota
	b = iota
)
const (
	name = "menglu"
	c    = iota
	d    = iota
)

type query func(string) string

func exec(name string, vs ...query) string {
	ch := make(chan string)
	fn := func(i int) {
		fmt.Println(vs[i](name))
		ch <- vs[i](name)
	}
	for i, _ := range vs {
		fmt.Println(i)
		go fn(i)
	}
	fmt.Println("return ch")
	return <-ch
}

type Girl struct {
	Name       string `json:"name"`
	DressColor string `json:"dress_color"`
}

func (g *Girl) SetColor(color string) {
	g.DressColor = color
}
func (g Girl) JSON() string {
	data, _ := json.Marshal(&g)
	return string(data)
}

type Tree struct {
	data  int
	Left  *Tree
	Right *Tree
}

func create(index int, value []int) (T *Tree) {
	T = &Tree{}
	T.data = value[index-1]
	fmt.Printf("index%v\n", index)
	if index < len(value)-1 && 2*index <= len(value) && 2*index+1 <= len(value) {
		T.Left = create(2*index, value)
		T.Right = create(2*index+1, value)
	}

	return T
}

func show(treeNode *Tree) {
	if treeNode != nil {
		fmt.Printf("%v", treeNode.data)
		if treeNode.Left != nil {
			show(treeNode.Left)
		}
		if treeNode.Right != nil {
			show(treeNode.Right)
		}
	} else {
		return
	}
}

//依靠队列顺序输出
func show1(treeNode *Tree) {
	l := list.New()
	l.PushBack(treeNode)

	for treeNode != nil {
		if l.Front() != nil {
			fmt.Printf("%v", l.Front().Value.(*Tree).data)
			treeNode = l.Front().Value.(*Tree)
		} else {
			break
		}

		if treeNode.Left != nil {
			l.PushBack(treeNode.Left)
		}
		if treeNode.Right != nil {
			l.PushBack(treeNode.Right)
		}
		if l.Front() != nil {
			l.Remove(l.Front())
		}
	}
}

func isSymmetric(root *Tree) bool {
	return check(root, root)
}

func check(p, q *Tree) bool {
	if p == nil && q == nil {
		return true
	}
	if p == nil || q == nil {
		return false
	}

	return p.data == q.data && check(p.Left, q.Right) && check(p.Right, q.Left)
}

//层次遍历树
func levelOrder(root *Tree) [][]int {
	ret := [][]int{}
	if root == nil {
		return ret
	}
	q := []*Tree{root}

	for i := 0; len(q) > 0; i++ {
		ret = append(ret, []int{})
		p := []*Tree{}
		for j := 0; j < len(q); j++ {
			node := q[j]
			ret[i] = append(ret[i], node.data)
			if node.Left != nil {
				p = append(p, node.Left)
			}
			if node.Right != nil {
				p = append(p, node.Right)
			}
		}
		q = p
	}

	return ret
}

func maxProfit(prices []int) int {
	if len(prices) < 2 {
		return 0
	}
	K := 2
	var dp [][][]int
	// dp[0][0][0] = 0, dp[0][0][1] = -prices[0]
	// dp[i][k][0] = max(dp[i-1][k][0], dp[i-1][k][1]+prices[i])
	// dp[i][k][1] = max(dp[i-1][k][1], dp[i-1][k - 1][0]- prices[i])

	for i := 0; i < len(prices); i++ {
		var tmp [][]int
		for k := K; k >= 0; k-- {
			var status = make([]int, 2)
			status[0] = 0
			status[1] = 0
			tmp = append(tmp, status)
		}
		dp = append(dp, tmp)
	}

	for i := 0; i < len(prices); i++ {
		for k := K; k > 0; k-- {
			if i == 0 {
				dp[i][k][1] = -prices[0]
			} else {
				dp[i][k][0] = max(dp[i-1][k][0], dp[i-1][k][1]+prices[i])
				dp[i][k][1] = max(dp[i-1][k][1], dp[i-1][k-1][0]-prices[i])
			}
		}
	}

	res := 0
	for k := K; k > 0; k-- {
		res = max(dp[len(prices)-1][k][0], res)
	}

	return res

}

func max(x, y int) int {
	if x > y {
		return x
	}

	return y
}

func main() {

	//chRe := make(chan int, 100)
	var wg1 sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			testRequest()
		}()
	}

	wg1.Wait()
	/*for i := 0; i < 100; i++ {
		<-chRe
	}*/

	fmt.Println("request complete")
	test := []int{3, 3, 5, 0, 0, 3, 1, 4}
	maxamount := maxProfit(test)
	fmt.Println(maxamount)
	value := []int{1, 2, 2, 3, 4, 4, 3}
	TreeRoot := create(1, value)
	fmt.Println("is sdd tree")
	fmt.Println(isSymmetric(TreeRoot))
	fmt.Println(levelOrder(TreeRoot))

	fmt.Println([...]string{"1"} == [...]string{"1"})
	fmt.Println([1]string{"1"} == [1]string{"1"})
	str1 := []string{"a", "b", "c"}
	str2 := str1[1:]
	fmt.Println(str2)
	str2[1] = "new"
	fmt.Println(str2)
	str2 = append(str2, "z", "x", "y")
	fmt.Println(str1)
	fmt.Println(str2)

	g := Girl{Name: "menglu"}
	g.SetColor("white")
	fmt.Println(g.JSON())

	ret := exec("111", func(n string) string {
		return n + "func1"
	}, func(n string) string {
		return n + "func2"
	}, func(n string) string {
		return n + "func3"
	}, func(n string) string {
		return n + "func4"
	})
	fmt.Println(ret)

	fmt.Println(a)
	fmt.Println(b)
	fmt.Println(c)
	fmt.Println(d)
	var x string
	if x == "" {
		x = "default"
	}
	fmt.Println(x)
	//var lo sync.Mutex
	var wg sync.WaitGroup

	go func() {
		wg.Add(1)
		time.Sleep(3 * time.Second)
		wg.Done()
	}()

	re := WaitTimeout(&wg, 2)
	fmt.Println(re)
	/*
		total := 0
		sum := 0
			for i := 1; i <= 10; i++ {
				sum += i
				//lo.Lock()
				wg.Add(1)
				go func() {
					total += i
					fmt.Println(total)
					time.Sleep(1 * time.Second)
					wg.Done()
					//lo.Unlock()
				}()
				WaitTimeout(&wg, 2)
			}

			fmt.Printf("total:%d sum %d", total, sum)*/

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go handle(ctx, 500*time.Millisecond)
	select {
	case <-ctx.Done():
		fmt.Println("main", ctx.Err())
	}

	c := &Cat{title: "test"}
	c.Quack()
	c.Test()
	fmt.Println(c.title)

	var t *TestStruct
	fmt.Println(t)
	fmt.Println(NilOrNot(t))

	ch2 := make(chan int)
	select {
	case i := <-ch2:
		println(i)

	default:
		println("default")
	}

	/* log.SetLevel(log.DebugLevel)
	file, err := os.OpenFile("logrus.log", os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		log.SetOutput(file)
	} else {
		log.Info("Failed to log to file, using default stderr")
	}

	taskChan := make(chan int, 3)
	taskId := 1

	go func() {
		for {
			if len(taskChan) < 3 {
				go run(taskId, taskChan)
				taskId++
			} else {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	log.Fatal(http.ListenAndServe(":9003", nil)) */

	userCount := 10
	ch := make(chan int, 5)
	for i := 0; i < userCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range ch {
				fmt.Printf("go func: %d, time: %d\n", d, time.Now().Unix())
				time.Sleep(time.Second * time.Duration(d))
			}
		}()
	}

	for i := 0; i < 10; i++ {
		ch <- 1
		ch <- 2
		//time.Sleep(time.Second)
	}

	close(ch)
	wg.Wait()

	mp := map[interface{}]interface{}{
		"gaoziwen": 26,
		"zhangsan": 27,
		"lisi":     28,
	}

	f := selfInfo
	EachFunc(mp, f)

	DynamicInvoke(new(MyStr1), "Test1")
	DynamicInvoke(new(MyStr2), "Test2", 5, "bbbb")

	key := "Mst@1234576"
	text := "dsfasdf2399dsa34@234109+-=0-0d2您好啊eee朋友"

	mstAes := MstAes{key: key}
	encstr, _ := mstAes.encrypt(text)
	fmt.Println(encstr)
	desstr, _ := mstAes.decrypt(encstr)
	fmt.Println(desstr)

	mstAes2 := MstAes{key: "key"}
	encstr2, _ := mstAes2.encrypt(text)
	fmt.Println(encstr2)
	desstr2, _ := mstAes2.decrypt(encstr2)
	fmt.Println(desstr2)

	var char string
	var firstChar string
	i := 51
	headerPage := int(math.Floor(float64(i / 26)))
	fmt.Println(headerPage)
	if headerPage > 0 {
		firstChar = fmt.Sprintf("%c", rune(64+headerPage))
	}
	fmt.Println(firstChar)
	char = firstChar + fmt.Sprintf("%c", rune(65+i-headerPage*26))

	fmt.Println(char)
}

type MstAes struct {
	key string
}

//填充
func (MstAes) pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func (MstAes) unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func (m *MstAes) encrypt(text string) (string, error) {
	byteKey := md5.Sum([]byte(m.key))
	md5str := fmt.Sprintf("%x", byteKey)

	block, err := aes.NewCipher([]byte(md5str))
	if err != nil {
		return "", err
	}

	msg := m.pad([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))

	//随机生成向量
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	finalMsg := (base64.StdEncoding.EncodeToString(ciphertext))
	finalMsg = strings.Replace(finalMsg, "+", "-", -1)
	finalMsg = strings.Replace(finalMsg, "/", "_", -1)
	finalMsg = strings.TrimRight(finalMsg, "=")

	return finalMsg, nil
}

func (m *MstAes) decrypt(text string) (string, error) {
	byteKey := md5.Sum([]byte(m.key))
	md5str := fmt.Sprintf("%x", byteKey)

	block, err := aes.NewCipher([]byte(md5str))
	if err != nil {
		return "", err
	}

	text = strings.Replace(text, "-", "+", -1)
	text = strings.Replace(text, "_", "/", -1)

	padLen := 4 - len(text)%4
	if padLen < 4 {
		for i := 0; i < padLen; i++ {
			text += "="
		}
	}

	decodedMsg, err := base64.StdEncoding.DecodeString((text))

	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(msg, msg)

	unpadMsg, err := m.unpad(msg)
	if err != nil {
		return "", err
	}

	return string(unpadMsg), nil
}
