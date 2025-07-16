#include <unreliable.h>
#include <iostream>
#include <chrono>

int main(int argc, char* argv[]) {
    // if (argc < 2) {
    //     std::cerr << "Usage: " << argv[0] << " <path_to_binary>\n";
    //     return 1;
    // }
    // const char* filePath = argv[1];

    // auto start = std::chrono::high_resolution_clock::now();
    // auto results = findPatches(filePath, [](int percent) {
    //     std::cout << "\rProgress: " << percent << "% " << std::flush;
    // });
    // for (const auto& [name, addr, imm] : results) {
    //     std::cout << "0x" << std::hex << addr << " -> " << imm << " : " << name << '\n';
    // }
    // auto end = std::chrono::high_resolution_clock::now();
    // std::chrono::duration<double> duration = end - start;

    // std::cout << "Finished " << duration.count() << " seconds.\n";

    // return 0;
}
