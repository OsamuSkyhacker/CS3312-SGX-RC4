#include <stdio.h>
#include <iostream>
#include <iomanip>  // 用于 std::hex 和 std::setw
#include <string>   // 用于 std::string 和 std::getline
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

/* 全局 EID，由多个线程共享 */
sgx_enclave_id_t global_eid = 0;

// OCall 实现
void ocall_print(const char* str) {
    printf("%s\n", str);
}

void print_hex(const char* title, const unsigned char* data, size_t data_len) {
    std::cout << title;
    for (size_t i = 0; i < data_len; ++i) {
        printf("%02x ", data[i]);
    }
    std::cout << std::endl;
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "初始化 Enclave 失败。" << std::endl;
        return 1;
    }

    std::string input_string;
    std::cout << "请输入要加密的字符串: ";
    std::getline(std::cin, input_string);  // 从标准输入读取一行

    const unsigned char rc4_key[] = "my_secret_key";
    sgx_status_t status = rc4_init(global_eid, rc4_key, sizeof(rc4_key) - 1);
    if (status != SGX_SUCCESS) {
        std::cout << "RC4 密钥初始化失败。" << std::endl;
        return 1;
    }

    unsigned char* data = new unsigned char[input_string.size() + 1];
    memcpy(data, input_string.c_str(), input_string.size() + 1);
    size_t data_len = input_string.size();

    std::cout << "原始数据: " << data << std::endl;
    print_hex("原始数据(HEX): ", data, data_len);

    // 加密数据
    status = rc4_crypt(global_eid, data, data_len);
    if (status != SGX_SUCCESS) {
        std::cout << "加密失败。" << std::endl;
        delete[] data;
        return 1;
    }
    std::cout << std::endl;
    print_hex("加密数据(HEX): ", data, data_len);
    std::cout << std::endl;


    // 重新初始化 RC4 状态
    rc4_init(global_eid, rc4_key, sizeof(rc4_key) - 1);

    // 解密数据
    status = rc4_crypt(global_eid, data, data_len);
    if (status != SGX_SUCCESS) {
        std::cout << "解密失败。" << std::endl;
        delete[] data;
        return 1;
    }

    std::cout << "解密数据: " << data << std::endl;
    print_hex("解密数据(HEX): ", data, data_len);

    delete[] data;  // 不要忘记释放内存
    return 0;
}