# vrscene2json

Fast C++14 parser that converts V-Ray `.vrscene` files to JSON.

## Build

Requires CMake 3.10+ and a C++14 compiler.

### Linux / macOS

```bash
cmake -B build
cmake --build build
```

### Windows (MSVC)

From a Visual Studio developer prompt (x64):

```bash
cmake -B build -G "NMake Makefiles"
cmake --build build
```

Or open the folder in Visual Studio and let it configure natively.

## Usage

```bash
vrscene2json [-u|--uncompressed] input.vrscene [output.json]
```

- **Default**: binary arrays (`ListIntHex`, `ListVectorHex`) are output as base64-encoded strings
- **`-u`**: output binary arrays as raw JSON arrays

### Encoded format

Large binary data is serialized as:

```json
{ "enc": "base64", "type": "float32", "count": 123, "data": "AAAAAAB..." }
```

Decode the base64 string and reinterpret as `float32[]` (little-endian).

## Supported vrscene features

- Plugin block extraction (`Type name { ... }`)
- Property values: strings, numbers, AColor/Color, Vector, Transform, List, ListString, identifiers
- Binary encodings: ZIPB (base41+zlib), ZIPC (base64+zlib), plain hex
- Line comments (`//`)
