package main

import (
    "fmt"
    "io/ioutil"
)

var fname = "data.txt"

func main() {
    dat, err := ioutil.ReadFile(fname)
    if err != nil {
        panic(err)
    }

    fmt.Printf(string(dat))
}
