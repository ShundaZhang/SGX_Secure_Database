//
//g++ -o fgets fgets.cpp

#include <iostream>
#include <cstring>

bool f_gets(char *out, size_t out_len, const char *input, size_t index) {
    size_t pos = 0;
    size_t start = 0;
    size_t current_index = 0;

    // 迭代找到第index个以;结束的句子
    while ((pos = std::strchr(input + start, ';') - input) != std::string::npos) {
        if (current_index == index) {
            // 找到了第index个句子，计算句子长度
            size_t sentence_len = pos - start + 1;

            // 检查输出缓冲区是否足够大
            if (sentence_len >= out_len) {
                // 如果缓冲区不够大，返回错误
                return false;
            }

            // 复制句子到输出缓冲区
            std::strncpy(out, input + start, sentence_len);
            out[sentence_len] = '\0'; // 确保空字符终止
            return true;
        }

        // 更新起始位置和索引
        start = pos + 1;
        ++current_index;
    }

    // 如果到达这里，表示没有找到第index个句子
    return false;
}

int main() {
    const char *sql_data = "SELECT * FROM my_table;SHOW STATUS LIKE 'Ssl_cipher';";
    char buffer[256];
    size_t index = 0;

    if (f_gets(buffer, sizeof(buffer), sql_data, index)) {
        std::cout << "The " << index << "th sentence is: " << buffer << std::endl;
    } else {
        std::cout << "The " << index << "th sentence could not be found or buffer is too small." << std::endl;
    }

    return 0;
}

