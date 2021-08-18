# go-fuzz-headers
This repository contains various helper functions to be used with [go-fuzz](https://github.com/dvyukov/go-fuzz).


## Usage
Using go-fuzz-headers is easy. First create a new consumer with the bytes provided by the fuzzing engine:

```go
import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)
data := []byte{"R", "a", "n", "d", "o", "m"}
f := fuzz.NewConsumer(data)

```

This creates a "Consumer" that consumes the bytes of the input as it uses them to fuzz different types.

After that, `f` can be used to created fuzzed instances of different types. Below are some examples:

### Structs
One of its most useful features of go-fuzz-headers is its ability to fill structs will pseudo-random values.
go-fuzz-headers can be used to fuzz the fields of structs with a single line:
```go
type Person struct {
    Name string
    Age  int
}
p := Person{}
err := f.GenerateStruct(&Person)
```

This includes nested structs too. In this example, the fuzz Consumer will also insert values in p.BestFriend: 
```go
type PersonI struct {
    Name       string
    Age        int
    BestFriend Person2
}
type PersonII struct {
    Name string
    Age  int
}
p := PersonI{}
err := f.GenerateStruct(&Person1)
```

If the consumer should insert values for unexported fields as well as exported, this can be enabled with:

```go
f.AllowUnexportedFields()
```

...and disabled with:

```go
f.AllowUnexportedFields()
```

### Other types:

The `Consumer` can creates basic types:

```go
err := f.GetString() // Gets random string
err = f.GetInt() // Gets random integer
err = f.GetByte() // Gets random byte
err = f.GetBytes() // Gets random byte slice
err = f.GetBool() // Gets random boolean
err = f.FuzzMap(target_map) // Fills a map with values
err = f.TarBytes() // Gets bytes of a valid tar archive
```

Most APIs are added as they are needed.

 

## Status
The project is under development and will be updated regularly.

## References
go-fuzz-headers' approach to fuzzing structs is strongly inspired by [gofuzz](https://github.com/google/gofuzz).