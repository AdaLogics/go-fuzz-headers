package gofuzzheaders

import (
	"errors"
	"reflect"
)

type ConsumeFuzzer struct {
	data          []byte
	CommandPart   []byte
	RestOfArray   []byte
	NumberOfCalls int
	position      int
}

func IsDivisibleBy(n int, divisibleby int) bool {
	return (n % divisibleby) == 0
}

func NewConsumer(fuzzData []byte) *ConsumeFuzzer {
	f := &ConsumeFuzzer{data: fuzzData, position: 0}
	return f
}

func (f *ConsumeFuzzer) Split(minCalls, maxCalls int) error {
	if len(f.data) == 0 {
		return errors.New("Could not split")
	}
	numberOfCalls := int(f.data[0])
	if numberOfCalls < minCalls || numberOfCalls > maxCalls {
		return errors.New("Bad number of calls")

	}
	if len(f.data) < numberOfCalls+numberOfCalls+1 {
		return errors.New("Length of data does not match required parameters")
	}

	// Define part 2 and 3 of the data array
	commandPart := f.data[1 : numberOfCalls+1]
	restOfArray := f.data[numberOfCalls+1:]

	// Just a small check. It is necessary
	if len(commandPart) != numberOfCalls {
		return errors.New("Length of commandPart does not match number of calls")
	}

	// Check if restOfArray is divisible by numberOfCalls
	if !IsDivisibleBy(len(restOfArray), numberOfCalls) {
		return errors.New("Length of commandPart does not match number of calls")
	}
	f.CommandPart = commandPart
	f.RestOfArray = restOfArray
	f.NumberOfCalls = numberOfCalls
	return nil
}

func (f *ConsumeFuzzer) GenerateStruct(targetStruct interface{}) error {
	if f.position >= len(f.data) {
		return errors.New("Not enough bytes to proceed")
	}
	e := reflect.ValueOf(targetStruct).Elem()
	for i := 0; i < e.NumField(); i++ {
		fieldtype := e.Type().Field(i).Type.String()
		switch ft := fieldtype; ft {
		case "string":
			stringChunk, err := f.GetString()
			if err != nil {
				return err
			}
			e.Field(i).SetString(stringChunk)
		case "bool":
			newBool, err := f.GetBool()
			if err != nil {
				return err
			}
			e.Field(i).SetBool(newBool)
		case "int":
			newInt, err := f.GetInt()
			if err != nil {
				return err
			}
			e.Field(i).SetInt(int64(newInt))
		case "[]string":
			continue
		case "[]byte":
			newBytes, err := f.GetBytes()
			if err != nil {
				return err
			}
			e.Field(i).SetBytes(newBytes)
		default:
			continue
		}
	}
	return nil
}

func (f *ConsumeFuzzer) GetInt() (int, error) {
	if f.position >= len(f.data) {
		return 0, errors.New("Not enough bytes to create int")
	}
	returnInt := int(f.data[f.position])
	f.position++
	return returnInt, nil
}

func (f *ConsumeFuzzer) GetBytes() ([]byte, error) {
	if f.position >= len(f.data) {
		return nil, errors.New("Not enough bytes to create byte array")
	}
	length := int(f.data[f.position])
	if f.position+length >= len(f.data) {
		return nil, errors.New("Not enough bytes to create byte array")
	}
	b := f.data[f.position : f.position+length]
	f.position = f.position + length
	return b, nil
}

func (f *ConsumeFuzzer) GetString() (string, error) {
	if f.position >= len(f.data) {
		return "nil", errors.New("Not enough bytes to create string")
	}
	length := int(f.data[f.position])
	if f.position+length >= len(f.data) {
		return "nil", errors.New("Not enough bytes to create string")
	}
	str := string(f.data[f.position : f.position+length])
	f.position = f.position + length
	return str, nil
}

func (f *ConsumeFuzzer) GetBool() (bool, error) {
	if f.position >= len(f.data) {
		return false, errors.New("Not enough bytes to create bool")
	}
	if IsDivisibleBy(int(f.data[f.position]), 2) {
		f.position++
		return true, nil
	} else {
		f.position++
		return false, nil
	}
}
