#ifndef VTABLE_PROCESSOR_HPP
#define VTABLE_PROCESSOR_HPP

#include <fcntl.h>
#include <iostream>
#include <vector>
#include <libelf.h>
#include <cstring>
#include <unistd.h>
#include <string>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <gelf.h>

struct VTable {
    uint64_t address;
    std::vector<uint8_t> content;
    uint64_t len() const { return content.size(); }
};

#pragma pack(push, 1)
struct VTableHeader {
    long address;
    long len;
};
#pragma pack(pop)

struct LibraryInfo {
    std::string path;
    uint64_t base_address;
};

struct Symbol_info {
    std::string lib_name;
    uint64_t offset;
    uint64_t size;
};

struct Symbol {
    std::string name;
    uint64_t address;
    uint64_t type;  // relocation type
    int64_t addend;
};

extern std::unordered_map<std::string, LibraryInfo> lib_info;  // lib_name -> path and base_addr
extern std::unordered_map<std::string, Symbol_info> symbol_map;  // symbol name -> lib_name 、offset 和 size

extern std::unordered_map<uint64_t, Symbol> reloc_map;  // relocation offset -> symbol name

// Function declarations

/**
 * @brief Extracts the file name from a given file path.
 * 
 * @param path The full file path.
 * @return The extracted file name.
 */
std::string extractFileName(const std::string& path);

/**
 * @brief Parses the /proc/[pid]/maps file to gather loaded libraries and their base addresses.
 * 
 * @param pid The process ID for which to parse the maps.
 */
void parse_proc_maps(std::string pid);

/**
 * @brief Extracts symbols from loaded libraries in memory.
 */
void get_symbols_from_libs();

/**
 * @brief Checks if a section is a dynamic symbol section.
 * 
 * @param scn The ELF section.
 * @param shdr The section header.
 * @return True if the section is a dynamic symbol section, false otherwise.
 */
bool is_dynsym_section(Elf_Scn *scn, GElf_Shdr &shdr);

/**
 * @brief Checks if a section is a relocation dynamic section.
 * 
 * @param elf The ELF file object.
 * @param shstrndx The section header string index.
 * @param scn The ELF section.
 * @param shdr The section header.
 * @return True if the section is a relocation dynamic section, false otherwise.
 */
bool is_rela_dyn_section(Elf *elf, size_t shstrndx, Elf_Scn *scn, GElf_Shdr &shdr);

/**
 * @brief Extracts symbols and relocations from a given ELF file.
 * 
 * @param file_path The path to the ELF file.
 * @return 0 on success, non-zero on failure.
 */
int extract_symbols(std::string file_path);

/**
 * @brief Reads bytes at a given address in the ELF file.
 * 
 * @param file_path The path to the ELF file.
 * @param target_address The target address to read from.
 * @param num_bytes The number of bytes to read.
 * @return The value read from the target address.
 */
uint64_t read_bytes_at_address(const std::string &file_path, uint64_t target_address, size_t num_bytes);

/**
 * @brief Solves relocations and writes the vtable data to the output file.
 * 
 * @param file_path The path to the ELF file.
 * @param output_path The path to the output file where vtables will be written.
 */
void solve_relocations(std::string file_path, std::string output_path);

/**
 * @brief Processes vtables by parsing memory maps, extracting symbols, solving relocations, 
 *        and writing the results to the output file.
 * 
 * @param file_path The path to the ELF file.
 * @param pid The process ID to get loaded libraries from.
 * @param output_path The path to the output file.
 */
// void process_vtables(std::string file_path, std::string pid, std::string output_path);
void process_vtables(const std::string &bolted_binary_path, const std::string &target_pid, const std::string &v_table_bin_path);

#endif // VTABLE_PROCESSOR_HPP