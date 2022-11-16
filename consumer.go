package gofuzzheaders

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unsafe"

	securejoin "github.com/cyphar/filepath-securejoin"
)

var MaxTotalLen uint32 = 2000000

func SetMaxTotalLen(newLen uint32) {
	MaxTotalLen = newLen
}

type ConsumeFuzzer struct {
	data                 []byte
	CommandPart          []byte
	RestOfArray          []byte
	NumberOfCalls        int
	position             uint32
	fuzzUnexportedFields bool
	Funcs                map[reflect.Type]reflect.Value
}

func IsDivisibleBy(n int, divisibleby int) bool {
	return (n % divisibleby) == 0
}

func NewConsumer(fuzzData []byte) *ConsumeFuzzer {
	return &ConsumeFuzzer{
		data:  fuzzData,
		Funcs: make(map[reflect.Type]reflect.Value),
	}
}

func (f *ConsumeFuzzer) Split(minCalls, maxCalls int) error {
	if len(f.data) == 0 {
		return errors.New("could not split")
	}
	numberOfCalls := int(f.data[0])
	if numberOfCalls < minCalls || numberOfCalls > maxCalls {
		return errors.New("bad number of calls")
	}
	if len(f.data) < numberOfCalls+numberOfCalls+1 {
		return errors.New("length of data does not match required parameters")
	}

	// Define part 2 and 3 of the data array
	commandPart := f.data[1 : numberOfCalls+1]
	restOfArray := f.data[numberOfCalls+1:]

	// Just a small check. It is necessary
	if len(commandPart) != numberOfCalls {
		return errors.New("length of commandPart does not match number of calls")
	}

	// Check if restOfArray is divisible by numberOfCalls
	if !IsDivisibleBy(len(restOfArray), numberOfCalls) {
		return errors.New("length of commandPart does not match number of calls")
	}
	f.CommandPart = commandPart
	f.RestOfArray = restOfArray
	f.NumberOfCalls = numberOfCalls
	return nil
}

func (f *ConsumeFuzzer) AllowUnexportedFields() {
	f.fuzzUnexportedFields = true
}

func (f *ConsumeFuzzer) DisallowUnexportedFields() {
	f.fuzzUnexportedFields = false
}

func (f *ConsumeFuzzer) GenerateStruct(targetStruct interface{}) error {
	v := reflect.ValueOf(targetStruct)
	/*if !v.CanSet() {
		return errors.New("This interface cannot be set")
	}*/
	e := v.Elem()
	return f.fuzzStruct(e, false)
}

func (f *ConsumeFuzzer) setCustom(v reflect.Value) error {
	// First: see if we have a fuzz function for it.
	doCustom, ok := f.Funcs[v.Type()]
	if !ok {
		return fmt.Errorf("could not find a custom function")
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			if !v.CanSet() {
				return fmt.Errorf("could not use a custom function")
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
	case reflect.Map:
		if v.IsNil() {
			if !v.CanSet() {
				return fmt.Errorf("could not use a custom function")
			}
			v.Set(reflect.MakeMap(v.Type()))
		}
	default:
		return fmt.Errorf("could not use a custom function")
	}

	verr := doCustom.Call([]reflect.Value{v, reflect.ValueOf(Continue{
		F: f,
	})})

	// check if we return an error
	if verr[0].IsNil() {
		return nil
	}
	return fmt.Errorf("could not use a custom function")
}

func (f *ConsumeFuzzer) fuzzStruct(e reflect.Value, customFunctions bool) error {
	// We check if we should check for custom functions
	if customFunctions {
		if e.IsValid() {
			if e.CanAddr() {
				err := f.setCustom(e.Addr())
				if err == nil {
					return nil
				}
			}
			/*	return f.setCustom(e)
				_, ok := f.Funcs[e.Type()]
				if ok {
					if e.CanAddr() {
						err := f.setCustom(e.Addr())
						if err == nil {
							return nil
						}
					}*/
			// return f.setCustom(e)
		}
	}

	switch e.Kind() {
	case reflect.Struct:
		for i := 0; i < e.NumField(); i++ {
			var v reflect.Value
			if !e.Field(i).CanSet() {
				if f.fuzzUnexportedFields {
					v = reflect.NewAt(e.Field(i).Type(), unsafe.Pointer(e.Field(i).UnsafeAddr())).Elem()
				}
				err := f.fuzzStruct(v, customFunctions)
				if err != nil {
					return err
				}
			} else {
				/*if e.Field(i).Kind() == reflect.Struct {
					//e = reflect.NewAt(e.Type(), unsafe.Pointer(e.UnsafeAddr())).Elem()
					//e.Field(i).Set(reflect.New(e.Field(i).Type()))
				}*/
				v = e.Field(i)
				// v = reflect.New(e.Field(i).Type())
				err := f.fuzzStruct(v, customFunctions)
				if err != nil {
					return err
				}
				/*if e.Field(i).CanSet() {
					e.Field(i).Set(v.Elem())
				}*/
			}
		}
	case reflect.String:
		str, err := f.GetString()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetString(str)
		}
	case reflect.Slice:
		var maxElements uint32
		// Byte slices should not be restricted
		if e.Type().String() == "[]uint8" {
			maxElements = 10000000
		} else {
			maxElements = 50
		}

		randQty, err := f.GetUint32()
		if err != nil {
			return err
		}
		var numOfElements uint32
		numOfElements = randQty % maxElements
		if (uint32(len(f.data)) - f.position) < numOfElements {
			numOfElements = uint32(len(f.data)) - f.position
		}

		uu := reflect.MakeSlice(e.Type(), int(numOfElements), int(numOfElements))

		for i := 0; i < int(numOfElements); i++ {
			err := f.fuzzStruct(uu.Index(i), customFunctions)
			// If we have more than 10, then we can proceed with that.
			if err != nil {
				if i >= 10 {
					if e.CanSet() {
						e.Set(uu)
					}
					return nil
				} else {
					return err
				}
			}
		}
		if e.CanSet() {
			e.Set(uu)
		}
	case reflect.Uint16:
		newInt, err := f.GetUint16()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Uint32:
		newInt, err := f.GetUint32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Uint64:
		newInt, err := f.GetInt()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		newInt, err := f.GetInt()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetInt(int64(newInt))
		}
	case reflect.Float32:
		newFloat, err := f.GetFloat32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(float64(newFloat))
		}
	case reflect.Float64:
		newFloat, err := f.GetFloat64()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(float64(newFloat))
		}
	case reflect.Map:
		if e.CanSet() {
			e.Set(reflect.MakeMap(e.Type()))
			maxElements := 50
			randQty, err := f.GetInt()
			if err != nil {
				return err
			}
			numOfElements := randQty % maxElements
			for i := 0; i < numOfElements; i++ {
				key := reflect.New(e.Type().Key()).Elem()
				err := f.fuzzStruct(key, customFunctions)
				if err != nil {
					return err
				}
				val := reflect.New(e.Type().Elem()).Elem()
				err = f.fuzzStruct(val, customFunctions)
				if err != nil {
					return err
				}
				e.SetMapIndex(key, val)
			}
		}
	case reflect.Ptr:
		if e.CanSet() {
			e.Set(reflect.New(e.Type().Elem()))
			err := f.fuzzStruct(e.Elem(), customFunctions)
			if err != nil {
				return err
			}
			return nil
		}
	case reflect.Uint8:
		b, err := f.GetByte()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(b))
		}
	default:
		return nil
	}
	return nil
}

func (f *ConsumeFuzzer) GetStringArray() (reflect.Value, error) {
	// The max size of the array:
	max := uint32(20)

	arraySize := f.position
	if arraySize > max {
		arraySize = max
	}
	elemType := reflect.TypeOf("string")
	stringArray := reflect.MakeSlice(reflect.SliceOf(elemType), int(arraySize), int(arraySize))
	if f.position+arraySize >= uint32(len(f.data)) {
		return stringArray, errors.New("could not make string array")
	}

	for i := 0; i < int(arraySize); i++ {
		stringSize := uint32(f.data[f.position])

		if f.position+stringSize >= uint32(len(f.data)) {
			return stringArray, nil
		}
		stringToAppend := string(f.data[f.position : f.position+stringSize])
		strVal := reflect.ValueOf(stringToAppend)
		stringArray = reflect.Append(stringArray, strVal)
		f.position += stringSize
	}
	return stringArray, nil
}

func (f *ConsumeFuzzer) GetInt() (int, error) {
	if f.position >= uint32(len(f.data)) {
		return 0, errors.New("not enough bytes to create int")
	}
	returnInt := int(f.data[f.position])
	f.position++
	return returnInt, nil
}

func (f *ConsumeFuzzer) GetByte() (byte, error) {
	if len(f.data) == 0 {
		return 0x00, errors.New("not enough bytes to get byte")
	}
	if f.position >= uint32(len(f.data)) {
		return 0x00, errors.New("not enough bytes to get byte")
	}
	returnByte := f.data[f.position]
	f.position++
	return returnByte, nil
}

func (f *ConsumeFuzzer) GetNBytes(numberOfBytes int) ([]byte, error) {
	returnBytes := make([]byte, 0)
	if len(f.data) == 0 {
		return returnBytes, errors.New("not enough bytes to get byte")
	}
	if f.position >= uint32(len(f.data)) {
		return returnBytes, errors.New("not enough bytes to get byte")
	}
	for i := 0; i < numberOfBytes; i++ {
		newByte, err := f.GetByte()
		if err != nil {
			return returnBytes, err
		}
		returnBytes = append(returnBytes, newByte)
	}
	return returnBytes, nil
}

func (f *ConsumeFuzzer) GetUint16() (uint16, error) {
	u16, err := f.GetNBytes(2)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		return binary.LittleEndian.Uint16(u16), nil
	}
	return binary.BigEndian.Uint16(u16), nil
}

func (f *ConsumeFuzzer) GetUint32() (uint32, error) {
	u32, err := f.GetNBytes(4)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		return binary.LittleEndian.Uint32(u32), nil
	}
	return binary.BigEndian.Uint32(u32), nil
}

func (f *ConsumeFuzzer) GetUint64() (uint64, error) {
	u64, err := f.GetNBytes(8)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		return binary.LittleEndian.Uint64(u64), nil
	}
	return binary.BigEndian.Uint64(u64), nil
}

func (f *ConsumeFuzzer) GetBytes() ([]byte, error) {
	if len(f.data) == 0 || f.position >= uint32(len(f.data)) {
		return nil, errors.New("not enough bytes to create byte array")
	}
	length, err := f.GetUint32()
	if err != nil {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if f.position+length > MaxTotalLen {
		return nil, errors.New("created too large a string")
	}
	byteBegin := f.position - 1
	if byteBegin >= uint32(len(f.data)) {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if length == 0 {
		return nil, errors.New("zero-length is not supported")
	}
	if byteBegin+length >= uint32(len(f.data)) {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if byteBegin+length < byteBegin {
		return nil, errors.New("numbers overflow")
	}
	f.position = byteBegin + length
	return f.data[byteBegin:f.position], nil
}

func (f *ConsumeFuzzer) GetString() (string, error) {
	if f.position >= uint32(len(f.data)) {
		return "nil", errors.New("not enough bytes to create string")
	}
	length, err := f.GetUint32()
	if err != nil {
		return "nil", errors.New("not enough bytes to create string")
	}
	if f.position > MaxTotalLen {
		return "nil", errors.New("created too large a string")
	}
	byteBegin := f.position - 1
	if byteBegin >= uint32(len(f.data)) {
		return "nil", errors.New("not enough bytes to create string")
	}
	if byteBegin+length > uint32(len(f.data)) {
		return "nil", errors.New("not enough bytes to create string")
	}
	if byteBegin > byteBegin+length {
		return "nil", errors.New("numbers overflow")
	}
	f.position = byteBegin + length
	return string(f.data[byteBegin:f.position]), nil
}

func (f *ConsumeFuzzer) GetBool() (bool, error) {
	if f.position >= uint32(len(f.data)) {
		return false, errors.New("not enough bytes to create bool")
	}
	if IsDivisibleBy(int(f.data[f.position]), 2) {
		f.position++
		return true, nil
	} else {
		f.position++
		return false, nil
	}
}

func (f *ConsumeFuzzer) FuzzMap(m interface{}) error {
	return f.GenerateStruct(m)
}

func returnTarBytes(buf []byte) ([]byte, error) {
	// Count files
	var fileCounter int
	tr := tar.NewReader(bytes.NewReader(buf))
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		fileCounter++
	}
	if fileCounter > 4 {
		return buf, nil
	}
	return nil, fmt.Errorf("not enough files were created\n")
}

func setTarHeaderFormat(hdr *tar.Header, f *ConsumeFuzzer) error {
	ind, err := f.GetInt()
	if err != nil {
		return err
	}
	switch ind % 4 {
	case 0:
		hdr.Format = tar.FormatUnknown
	case 1:
		hdr.Format = tar.FormatUSTAR
	case 2:
		hdr.Format = tar.FormatPAX
	case 3:
		hdr.Format = tar.FormatGNU
	}
	return nil
}

func setTarHeaderTypeflag(hdr *tar.Header, f *ConsumeFuzzer) error {
	ind, err := f.GetInt()
	if err != nil {
		return err
	}
	switch ind % 13 {
	case 0:
		hdr.Typeflag = tar.TypeReg
	case 1:
		hdr.Typeflag = tar.TypeLink
		linkname, err := f.GetString()
		if err != nil {
			return err
		}
		hdr.Linkname = linkname
	case 2:
		hdr.Typeflag = tar.TypeSymlink
		linkname, err := f.GetString()
		if err != nil {
			return err
		}
		hdr.Linkname = linkname
	case 3:
		hdr.Typeflag = tar.TypeChar
	case 4:
		hdr.Typeflag = tar.TypeBlock
	case 5:
		hdr.Typeflag = tar.TypeDir
	case 6:
		hdr.Typeflag = tar.TypeFifo
	case 7:
		hdr.Typeflag = tar.TypeCont
	case 8:
		hdr.Typeflag = tar.TypeXHeader
	case 9:
		hdr.Typeflag = tar.TypeXGlobalHeader
	case 10:
		hdr.Typeflag = tar.TypeGNUSparse
	case 11:
		hdr.Typeflag = tar.TypeGNULongName
	case 12:
		hdr.Typeflag = tar.TypeGNULongLink
	}
	return nil
}

func (f *ConsumeFuzzer) createTarFileBody() ([]byte, error) {
	if len(f.data) == 0 || f.position >= uint32(len(f.data)) {
		return nil, errors.New("not enough bytes to create byte array")
	}
	length, err := f.GetUint32()
	if err != nil {
		return nil, errors.New("not enough bytes to create byte array")
	}

	// A bit of optimization to attempt to create a file body
	// when we don't have as many bytes left as "length"
	remainingBytes := (uint32(len(f.data)) - f.position)
	totalDataLen := uint32(len(f.data))
	if uint32(len(f.data))-f.position < 50 {
		if remainingBytes == 0 {
			return nil, errors.New("created too large a string")
		}
		length = length % remainingBytes
	} else if len(f.data) < 500 {
		if totalDataLen == 0 {
			return nil, errors.New("created too large a string")
		}
		length = length % totalDataLen
	}
	if f.position+length > MaxTotalLen {
		return nil, errors.New("created too large a string")
	}
	byteBegin := f.position - 1
	if byteBegin >= uint32(len(f.data)) {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if length == 0 {
		return nil, errors.New("zero-length is not supported")
	}
	if byteBegin+length >= uint32(len(f.data)) {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if byteBegin+length < byteBegin {
		return nil, errors.New("numbers overflow")
	}
	f.position = byteBegin + length
	return f.data[byteBegin:f.position], nil
}

// getTarFileName is similar to GetString(), but creates string based
// on the length of f.data to reduce the likelihood of overflowing
// f.data.
func (f *ConsumeFuzzer) getTarFilename() (string, error) {
	if f.position >= uint32(len(f.data)) {
		return "nil", errors.New("not enough bytes to create string")
	}
	length, err := f.GetUint32()
	if err != nil {
		return "nil", errors.New("not enough bytes to create string")
	}

	// A bit of optimization to attempt to create a file name
	// when we don't have as many bytes left as "length"
	remainingBytes := uint32(len(f.data)) - f.position
	totalDataLen := uint32(len(f.data))
	if uint32(len(f.data))-f.position < 50 {
		if remainingBytes == 0 {
			return "nil", errors.New("created too large a string")
		}
		length = length % remainingBytes
	} else if len(f.data) < 500 {
		if totalDataLen == 0 {
			return "nil", errors.New("created too large a string")
		}
		length = length % totalDataLen
	}
	if f.position > MaxTotalLen {
		return "nil", errors.New("created too large a string")
	}
	byteBegin := f.position - 1
	if byteBegin >= uint32(len(f.data)) {
		return "nil", errors.New("not enough bytes to create string")
	}
	if byteBegin+length > uint32(len(f.data)) {
		return "nil", errors.New("not enough bytes to create string")
	}
	if byteBegin > byteBegin+length {
		return "nil", errors.New("numbers overflow")
	}
	f.position = byteBegin + length
	return string(f.data[byteBegin:f.position]), nil
}

// TarBytes returns valid bytes for a tar archive
func (f *ConsumeFuzzer) TarBytes() ([]byte, error) {
	numberOfFiles, err := f.GetInt()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	defer tw.Close()

	maxNoOfFiles := 1000
	for i := 0; i < numberOfFiles%maxNoOfFiles; i++ {
		filename, err := f.getTarFilename()
		if err != nil {
			return returnTarBytes(buf.Bytes())
		}
		filebody, err := f.createTarFileBody()
		if err != nil {
			return returnTarBytes(buf.Bytes())
		}
		hdr := &tar.Header{}

		err = setTarHeaderTypeflag(hdr, f)
		if err != nil {
			return returnTarBytes(buf.Bytes())
		}

		sec, err := f.GetInt()
		if err != nil {
			return returnTarBytes(buf.Bytes())
		}

		nsec, err := f.GetInt()
		if err != nil {
			return returnTarBytes(buf.Bytes())
		}

		hdr.ModTime = time.Unix(int64(sec), int64(nsec))

		hdr.Name = filename
		hdr.Size = int64(len(filebody))
		hdr.Mode = 0o600

		err = setTarHeaderFormat(hdr, f)
		if err != nil {
			return returnTarBytes(buf.Bytes())
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return returnTarBytes(buf.Bytes())
		}
		if _, err := tw.Write(filebody); err != nil {
			return returnTarBytes(buf.Bytes())
		}
	}
	return returnTarBytes(buf.Bytes())
}

// CreateFiles creates pseudo-random files in rootDir.
// It creates subdirs and places the files there.
// It is the callers responsibility to ensure that
// rootDir exists.
func (f *ConsumeFuzzer) CreateFiles(rootDir string) error {
	numberOfFiles, err := f.GetInt()
	if err != nil {
		return err
	}
	maxNumberOfFiles := numberOfFiles % 4000 // This is completely arbitrary
	if maxNumberOfFiles == 0 {
		return errors.New("maxNumberOfFiles is nil")
	}

	var noOfCreatedFiles int
	for i := 0; i < maxNumberOfFiles; i++ {
		// The file to create:
		fileName, err := f.GetString()
		if err != nil {
			if noOfCreatedFiles > 0 {
				// If files have been created, we don't return an error.
				break
			} else {
				return errors.New("could not get fileName")
			}
		}
		fullFilePath, err := securejoin.SecureJoin(rootDir, fileName)
		if err != nil {
			return err
		}

		// Find the subdirectory of the file
		subDir := filepath.Dir(fileName)
		if subDir != "" && subDir != "." {
			// create the dir first

			// Avoid going outside the root dir
			if strings.Contains(subDir, "../") || (len(subDir) > 0 && subDir[0] == 47) || strings.Contains(subDir, "\\") {
				continue
			}
			dirPath := filepath.Join(rootDir, subDir)
			dirPath, err := securejoin.SecureJoin(rootDir, subDir)
			if err != nil {
				continue
			}
			if _, err := os.Stat(dirPath); os.IsNotExist(err) {
				err2 := os.MkdirAll(dirPath, 0o777)
				if err2 != nil {
					continue
				}
			}
			fullFilePath, err = securejoin.SecureJoin(dirPath, fileName)
			if err != nil {
				continue
			}
		} else {
			// Create symlink
			createSymlink, err := f.GetBool()
			if err != nil {
				if noOfCreatedFiles > 0 {
					break
				} else {
					return errors.New("could not create the symlink")
				}
			}
			if createSymlink {
				symlinkTarget, err := f.GetString()
				if err != nil {
					return err
				}
				os.Symlink(symlinkTarget, fullFilePath)
				// stop loop here, since a symlink needs no further action
				noOfCreatedFiles++
				continue
			}
			// We create a normal file
			fileContents, err := f.GetBytes()
			if err != nil {
				if noOfCreatedFiles > 0 {
					break
				} else {
					return errors.New("could not create the file")
				}
			}
			createdFile, err := os.Create(fullFilePath)
			if err != nil {
				createdFile.Close()
				continue
			}
			_, err = createdFile.Write(fileContents)
			if err != nil {
				createdFile.Close()
				continue
			}
			createdFile.Close()
			noOfCreatedFiles++
		}
	}
	return nil
}

// GetStringFrom returns a string that can only consist of characters
// included in possibleChars. It returns an error if the created string
// does not have the specified length.
func (f *ConsumeFuzzer) GetStringFrom(possibleChars string, length int) (string, error) {
	if (uint32(len(f.data)) - f.position) < uint32(length) {
		return "", errors.New("not enough bytes to create a string")
	}
	returnString := ""
	for i := 0; i < length; i++ {
		charIndex, err := f.GetInt()
		if err != nil {
			return returnString, err
		}
		charToAdd := string(possibleChars[charIndex%len(possibleChars)])
		returnString = fmt.Sprintf(returnString + charToAdd)
	}
	return returnString, nil
}

func (f *ConsumeFuzzer) GetRune() ([]rune, error) {
	stringToConvert, err := f.GetString()
	if err != nil {
		return []rune("nil"), err
	}
	return []rune(stringToConvert), nil
}

func (f *ConsumeFuzzer) GetFloat32() (float32, error) {
	u32, err := f.GetNBytes(4)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		u32LE := binary.LittleEndian.Uint32(u32)
		return math.Float32frombits(u32LE), nil
	}
	u32BE := binary.BigEndian.Uint32(u32)
	return math.Float32frombits(u32BE), nil
}

func (f *ConsumeFuzzer) GetFloat64() (float64, error) {
	u64, err := f.GetNBytes(8)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		u64LE := binary.LittleEndian.Uint64(u64)
		return math.Float64frombits(u64LE), nil
	}
	u64BE := binary.BigEndian.Uint64(u64)
	return math.Float64frombits(u64BE), nil
}

func (f *ConsumeFuzzer) CreateSlice(targetSlice interface{}) error {
	return f.GenerateStruct(targetSlice)
}
