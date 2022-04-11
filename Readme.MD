# Thư viện sử dụng:
1. aes.c + aes.h: Thư viện TinyAes để mã hoá và giải mã

# Cách sử dụng:
Ta dùng emscripten để build.

## Cách cài đặt emscripten
* Get the emsdk repo
git clone https://github.com/emscripten-core/emsdk.git

* Enter that directory
`cd emsdk`

* Fetch the latest version of the emsdk (not needed the first time you clone)
`git pull`

* Download and install the latest SDK tools.
`./emsdk install latest`

* Make the "latest" SDK "active" for the current user. (writes .emscripten file)
`./emsdk activate latest`

* Activate PATH and other environment variables in the current terminal
`emsdk_env.bat`

## Cú pháp build:
* Chạy npm run build
* Hoặc chạy trực tiếp lệnh build bằng emscripten:
`emcc src/crypto.c -Oz -s WASM=0 --memory-init-file 0 -s ENVIRONMENT='web' -o dist/aes.js -s EXPORTED_FUNCTIONS=['_encryptAES_CBC'] -s EXPORTED_RUNTIME_METHODS=['cwrap'] -s ALLOW_MEMORY_GROWTH=1`
<!-- emcc aes.c -Oz -s WASM=0 --memory-init-file 0 -s ENVIRONMENT='web' -o aes.js -s EXPORTED_FUNCTIONS='["_encryptAES_CBC","_decryptAES_CBC"]' -s EXPORTED_RUNTIME_METHODS='["cwrap"]' -s ALLOW_MEMORY_GROWTH=1 -->

## Giải thích:
* aes.c: File c của chúng ta, chứa 2 function encrypt và decrypt. Nếu muốn đổi IV và Secret Key thì ta sửa trong file này.
O3: Optimize code, -O3 sẽ minimum code sau build để nó gọn và nhẹ nhất
* -o aes.js: File đầu ra. Khi chạy lệnh trên ta sẽ có 2 file đầu ra là aes.js và aes.js.mem
* EXPORTED_FUNCTIONS: Pick function sẽ được export ra từ file aes.c
* EXPORTED_RUNTIME_METHODS: Chọn phương thức chạy, ở lệnh trên ta pick cả cwrap và ccall. Nếu như chỉ cần sử dụng cwrap hoặc chỉ cần sử dụng ccall thì pick cái sử dụng thôi. ()
* ALLOW_MEMORY_GROWTH: Cho phép tăng kích thước bộ nhớ.
* --memory-init-file 0: Không tách file memory init ra 1 file *.mem riêng (Nên set cái này để tiện khi sử dụng, chỉ lấy 1 file js thôi).
* -s ENVIRONMENT='web': Set cái này để file aes.js của chúng ta chạy được trong môi trường web. Nếu không set trường này thì trong file webpack.config.js ta phải set thêm trường `externals: "fs"` vào phần config, nếu không app sẽ lỗi.

## Cách call
### B1: Import file aes.js nhận được sau khi build (trong folder dist) vào file html của chúng ta. 
* Hoặc nếu muốn sử dụng nó trong 1 file javascript khác thì trong file dist/aes.js ta export Module ra, rồi import vào sử dụng như bình thường
* ![Untitled](https://user-images.githubusercontent.com/89797316/148716129-b0675ec7-30c1-420c-aa61-da8b98a25544.png)
### B2: Sử dụng 1 trong 2 method sau để call: 
### Đối số theo thứ tự là: "function sử dụng", "kiểu dữ liệu trả về", ["kiểu dữ liệu tham số truyền vào"], "tham số truyền vào"
* Encrypt:
let x = Module.cwrap("encryptAES","string",["string"])("hahahaha123+/12^*4");

* Decrypt:
let y = Module.cwrap("encryptAES","string",["string"])(x);

* Nếu muốn gọi hàm mã hoá và giải mã nhiều lần, thì ta có thể làm như sau:
##### const encryptFunction = Module.cwrap("encryptAES","string",["string"]);
##### encryptFunction("hahahaha123+/12^*4");
##### encryptFunction("hahbáạksabjksa123+/12^*4");
##### encryptFunction("871hsáunjậksjnkấn");

## Lưu ý
1. Nếu muốn thay đổi key và iv thì vào file src/crypto.c sửa sau đó chạy `npm run build` để build lại là được.
2. Hàm encrypt sẽ trả về hex string của data đã mã hoá chứ không phải base 64
* Encrypt - Input: Plain text, Output: Hex string (Lưu ý dùng mã hoá này sẽ trả ra 1 chuỗi hex string chứ không phải là trả ra 1 chuỗi base64 nhé)
3. Hàm decrypt cũng nhận tham số truyền vào hex string chứ không phải base 64
* Decrypt - Input: Hex string, Output: Plain text
