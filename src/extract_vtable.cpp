#include <iostream>
#include <iomanip>
#include <vector>
#include <unordered_map>
#include <string>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <cstring>
#include <unistd.h>
#include <fstream>
#include <cstdio>

struct LibraryInfo {
    std::string path;
    uint64_t base_address;
};

struct Symbol_info {
    std::string lib_name;
    uint64_t offset;
    uint64_t size;
};

std::unordered_map<std::string, LibraryInfo> lib_info;  // lib_name -> path and base_addr
std::unordered_map<std::string, Symbol_info> symbol_map;  // symbol name -> lib_name 、offset 和 size

struct Symbol {
    std::string name;
    uint64_t address;
    uint64_t type;  // relocation type
    int64_t addend;
};
std::unordered_map<uint64_t, Symbol> reloc_map;  // relocation offset -> symbol name

struct SymbolInfo {
    std::string name;
    GElf_Addr address;
    GElf_Xword size;
    std::vector<uint8_t> content;
};

struct VTableEntry {
    GElf_Addr content;
    bool is_dynamic;
    std::string symbol_name;
    std::string reloc_type;
    GElf_Addr base_address;
};

struct VTableInfo {
    std::string name;
    GElf_Addr address;
    GElf_Xword size;
    std::vector<uint8_t> raw_data;
    std::vector<VTableEntry> entries;
};

std::vector<VTableInfo> vtables;

std::string extractFileName(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

void parse_proc_maps(std::string pid) {
    std::ifstream maps("/proc/" + pid + "/maps");
    if (!maps.is_open()) {
        printf("Failed to open /proc/%s/maps \n", pid.c_str());
    }

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(".so") != std::string::npos) {
            std::istringstream iss(line);
            uint64_t start, end;
            char dash; 
            char perms[5];
            std::string path;

            if (!(iss >> std::hex >> start)) continue;
            if (!(iss >> dash) || dash != '-') continue;
            if (!(iss >> std::hex >> end)) continue;
            if (!(iss >> perms)) continue;

            std::string rest;
            std::getline(iss >> std::ws, rest);
            path = rest.substr(rest.find_last_of(' ') + 1);
            std::string name = extractFileName(path);

            if (lib_info.find(name) == lib_info.end()) {
                lib_info[name] = {path, start};
            }
        }
    }
}

void get_symbols_from_libs() {
    elf_version(EV_CURRENT);

    for (auto [lib_name, lib] : lib_info) {
        std::string lib_path = lib.path;

        int fd = open(lib_path.c_str(), O_RDONLY);
        if (fd == -1) {
            perror(("cannot open lib: " + lib_path).c_str());
            continue;
        }

        Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
        if (!elf) {
            fprintf(stderr, "ELF open failed: %s\n", elf_errmsg(elf_errno()));
            close(fd);
            continue;
        }
        Elf_Scn* scn = nullptr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            if (gelf_getshdr(scn, &shdr) != &shdr) {
                fprintf(stderr, "get section header failed: %s\n", elf_errmsg(elf_errno()));
                continue;
            }

            if (shdr.sh_type != SHT_DYNSYM) continue;

            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                fprintf(stderr, "cannot read symbols\n");
                continue;
            }

            size_t num_syms = shdr.sh_size / shdr.sh_entsize;
            std::vector<GElf_Sym> symbolsOfLib(num_syms);
            for (size_t i = 0; i < num_syms; ++i) {
                if (gelf_getsym(data, i, &symbolsOfLib[i]) != &symbolsOfLib[i]) {
                    fprintf(stderr, "read symbol failed: %s\n", elf_errmsg(elf_errno()));
                    continue;
                }
            }

            for (size_t i = 0; i < num_syms; ++i) {
                const GElf_Sym& sym = symbolsOfLib[i];
                const char* full_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!full_name || sym.st_shndx == SHN_UNDEF) continue;
                const char* version_sep = strchr(full_name, '@');
                std::string name(version_sep ? 
                                std::string(full_name, version_sep - full_name) : 
                                full_name);

                if (name.find("_Z") != 0) continue;
                size_t size = sym.st_size;
                if (size == 0 && i + 1 < num_syms) {
                    const GElf_Sym& next_sym = symbolsOfLib[i+1];
                    if (next_sym.st_value > sym.st_value) {
                        size = next_sym.st_value - sym.st_value;
                    }
                }
                symbol_map[name] = {lib_name, sym.st_value, size};
            }
        }
        elf_end(elf);
        close(fd);
    }
}


bool is_dynsym_section(Elf_Scn *scn, GElf_Shdr &shdr) {
    return (shdr.sh_type == SHT_DYNSYM);
}

bool is_rela_dyn_section(Elf *elf, size_t shstrndx, Elf_Scn *scn, GElf_Shdr &shdr) {
    return (shdr.sh_type == SHT_RELA && 
            strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".rela.dyn") == 0);
}

int extract_dynamic_symbols(std::string file_path) {
    elf_version(EV_CURRENT);
    int fd = open(file_path.c_str(), O_RDONLY);
    Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);

    size_t shstrndx;
    elf_getshdrstrndx(elf, &shstrndx);

    Elf_Scn *scn = nullptr;
    Elf_Scn *dynsym_scn = nullptr;
    Elf_Scn *rela_dyn_scn = nullptr;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);

        if (is_dynsym_section(scn, shdr)) {
            dynsym_scn = scn;
        } else if (is_rela_dyn_section(elf, shstrndx, scn, shdr)) {
            rela_dyn_scn = scn;
        }
    }

    if (!dynsym_scn || !rela_dyn_scn) {
        std::cerr << "Failed to find .dynsym or .rela.dyn sections!" << std::endl;
        return 1;
    }

    GElf_Shdr dynsym_shdr;
    gelf_getshdr(dynsym_scn, &dynsym_shdr);
    Elf_Data *dynsym_data = elf_getdata(dynsym_scn, nullptr);
    size_t num_symbols = dynsym_shdr.sh_size / dynsym_shdr.sh_entsize;

    std::vector<GElf_Sym> dynsyms;
    for (size_t i = 0; i < num_symbols; i++) {
        GElf_Sym sym;
        gelf_getsym(dynsym_data, i, &sym);
        dynsyms.push_back(sym);
    }

    GElf_Shdr rela_dyn_shdr;
    gelf_getshdr(rela_dyn_scn, &rela_dyn_shdr);
    Elf_Data *rela_data = elf_getdata(rela_dyn_scn, nullptr);
    size_t num_rela = rela_dyn_shdr.sh_size / rela_dyn_shdr.sh_entsize;

    for (size_t i = 0; i < num_rela; i++) {
        GElf_Rela rela;
        gelf_getrela(rela_data, i, &rela);

        uint32_t sym_idx = GELF_R_SYM(rela.r_info);

        if (sym_idx >= dynsyms.size()) {
            std::cerr << "Invalid symbol index: " << sym_idx << std::endl;
            continue;
        }

        GElf_Sym &sym = dynsyms[sym_idx];
        const char *sym_name = elf_strptr(elf, dynsym_shdr.sh_link, sym.st_name);
        if (sym_name == nullptr) continue;
        if (sym_name[0] != '_' || sym_name[1] != 'Z') continue;
        reloc_map[rela.r_offset] = {sym_name, rela.r_offset, GELF_R_TYPE(rela.r_info), rela.r_addend};
        // printf("offset: %lx, name: %s, type: %lx, addend: %lx\n", rela.r_offset, sym_name, GELF_R_TYPE(rela.r_info), rela.r_addend);
    }

    elf_end(elf);
    close(fd);
    return 0;
}

void parse_vtable_entries(Elf *elf,VTableInfo &vtable) {
    int elf_class = gelf_getclass(elf);
    size_t ptr_size = (elf_class == ELFCLASS32) ? 4 : 8;
    const uint8_t* data_ptr = vtable.raw_data.data();
    size_t data_size = vtable.raw_data.size();
    
    size_t offset = 0;
    size_t max_entries = (data_size - ptr_size) / ptr_size;

    for (size_t i = 0; i < max_entries; ++i) {
        if (offset + ptr_size > data_size) break;

        GElf_Addr entry_content = 0;
        if (elf_class == ELFCLASS32) {
            entry_content = *reinterpret_cast<const uint32_t*>(data_ptr + offset);
        } else {
            entry_content = *reinterpret_cast<const uint64_t*>(data_ptr + offset);
        }

        const GElf_Addr entry_addr = vtable.address + offset;
        VTableEntry entry;
        entry.content = entry_content;
        entry.base_address = entry_addr;
        entry.is_dynamic = false;
        entry.symbol_name.clear();
        entry.reloc_type.clear();

        auto reloc_it = reloc_map.find(entry_addr);
        if (reloc_it != reloc_map.end()) {
            entry.symbol_name = reloc_it->second.name;
            entry.reloc_type = reloc_it->second.type;
            entry.is_dynamic = true;
            Symbol_info sym = symbol_map[reloc_it->second.name];
            switch (reloc_it->second.type) {
                case 257:
                    entry.content = lib_info[sym.lib_name].base_address + sym.offset + reloc_it->second.addend;
                    break;
                case 1025:
                    entry.content = lib_info[sym.lib_name].base_address + sym.offset;
                    break;
                default:
                    break;
            }
        }

        vtable.entries.push_back(entry);
        offset += ptr_size;
    }
}

int get_vtables(std::string file_path) {
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "Failed to open file: " << file_path << "\n";
        return 1;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        std::cerr << "ELF parsing failed: " << elf_errmsg(-1) << "\n";
        close(fd);
        return 1;
    }

    Elf_Scn *scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) continue;

        if (shdr.sh_type == SHT_SYMTAB) {
            Elf_Data *data = elf_getdata(scn, nullptr);
            if (!data || !data->d_buf) continue;

            size_t count = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < count; ++i) {
                GElf_Sym sym;
                if (gelf_getsym(data, i, &sym) != &sym) continue;

                char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name) continue;
                if (name[0] != '_' || name[1] != 'Z') continue;

                SymbolInfo info;
                info.name = name;
                info.address = sym.st_value;
                info.size = sym.st_size;

                Elf_Scn *content_scn = elf_getscn(elf, sym.st_shndx);
                if (!content_scn) continue;
                
                GElf_Shdr content_shdr;
                if (gelf_getshdr(content_scn, &content_shdr) != &content_shdr) continue;
                
                Elf_Data *content_data = elf_rawdata(content_scn, nullptr);
                if (!content_data || !content_data->d_buf) continue;

                const size_t offset = sym.st_value - content_shdr.sh_addr;
                if (offset + sym.st_size > content_shdr.sh_size) continue;

                info.content.resize(sym.st_size);
                memcpy(info.content.data(), (char*)content_data->d_buf + offset, sym.st_size);
                if (info.name.find("_ZTV") == 0) {
                    if (!info.content.empty()) {
                        VTableInfo vtable;
                        vtable.name = info.name;
                        vtable.address = info.address;
                        vtable.size = info.size;
                        vtable.raw_data = info.content;
                        vtable.entries.clear();
                        vtables.push_back(vtable);
                    }
                }
            }
        }
    }
    int elf_class = gelf_getclass(elf);
    size_t ptr_size = (elf_class == ELFCLASS32) ? 4 : 8;
    // 为每个 vtable 生成 raw_data
    for (auto& vtable : vtables) {
        parse_vtable_entries(elf, vtable);   
        vtable.raw_data.clear(); // 清空原有数据
        for (const auto& entry : vtable.entries) {
            GElf_Addr content = entry.content;
            
            // 将 content 按小端序转换为字节流
            uint8_t bytes[8] = {0}; // 64位足够存储
            for (size_t i = 0; i < ptr_size; ++i) {
                bytes[i] = (content >> (i * 8)) & 0xFF;
            }
            
            // 追加到 raw_data
            vtable.raw_data.insert(
                vtable.raw_data.end(), 
                bytes, 
                bytes + ptr_size
            );
        }
/*
        printf("vtable name: %s, raw_data size: %lu\n", vtable.name.c_str(), vtable.raw_data.size());
        for (size_t i = 0; i < vtable.raw_data.size(); ++i) {
            printf("%02x ", vtable.raw_data[i]);
        }
        printf("\n");
*/
    }

    elf_end(elf);
    close(fd);
    return 0;
}

void save_vtables_to_binary(const std::vector<VTableInfo>& vtables,
                           const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open output file");
        return;
    }

    for (const auto& vtable : vtables) {
        // 强制使用固定宽度类型
        const uint64_t address = static_cast<uint64_t>(vtable.address);
        const uint64_t data_size = vtable.raw_data.size();  // 使用实际数据长度

        // 写入地址字段 (8字节)
        if (fwrite(&address, sizeof(address), 1, fp) != 1) {
            perror("Address write failed");
            fclose(fp);
            return;
        }

        // 写入数据长度字段 (8字节)
        if (fwrite(&data_size, sizeof(data_size), 1, fp) != 1) {
            perror("Size write failed");
            fclose(fp);
            return;
        }

        // 写入机器码数据
        if (data_size > 0) {
            const size_t written = fwrite(vtable.raw_data.data(), 1, data_size, fp);
        }
    }

    if (fclose(fp) != 0) {
        perror("File closure failed");
    }
}


void process_vtables(const std::string &bolted_binary_path, const std::string &target_pid, const std::string &v_table_bin_path) {
    parse_proc_maps(target_pid);
    get_symbols_from_libs();
    extract_dynamic_symbols(bolted_binary_path);
    get_vtables(bolted_binary_path);
    save_vtables_to_binary(vtables, v_table_bin_path.c_str());
}