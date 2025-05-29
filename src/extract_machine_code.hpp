#include "utils.hpp"
#include "boost_serialization.hpp"

using namespace std;

/*
 * for each unmoved functions, check any call instruction 
 * within that function and if the call's target is moved,
 * patch the call sites by changing the target.
 */
//void extract_call_sites(FILE* pFile, unordered_map<long, func_info>moved_func, unordered_map<long, func_info> func_in_call_stack, const ocolos_env* ocolos_environ);
__attribute__((always_inline)) inline void inlined_extract_call_sites(FILE* pFile, unordered_map<long, func_info> moved_func, unordered_map<long, func_info> func_in_call_stack, unordered_map<long, call_site_info> call_sites, unordered_map<long, vector<long> > call_sites_list, const ocolos_env* ocolos_environ);


__attribute__((always_inline)) inline void inlined_extract_call_sites(FILE* pFile, unordered_map<long, func_info> moved_func, unordered_map<long, func_info> func_in_call_stack, unordered_map<long, call_site_info> call_sites, unordered_map<long, vector<long> > call_sites_list, const ocolos_env* ocolos_environ){

   for (auto it = moved_func.begin(); it!=moved_func.end(); it++){
#ifdef Intel64
      if (call_sites_list.find(it->first)!=call_sites_list.end()){
         vector<long> caller_lists = call_sites_list[it->first];
         for (unsigned i=0; i<caller_lists.size(); i++){
            long addr = caller_lists[i];
            long belonged_func = call_sites[addr].belonged_func;
            if (func_in_call_stack.find(belonged_func)==func_in_call_stack.end()) continue;

            long base_addr = call_sites[addr].next_addr;
            long new_target_addr = it->second.moved_addr;
            long offset = new_target_addr - base_addr;
            vector<uint8_t> machine_code_line = convert_long_2_vec_uint8(offset);
            // write the virtual address + the size of the machine code
            // and machine code itself into a file
            long machine_code_address = addr;
            long machine_code_size = (long)(machine_code_line.size()+1);
            fwrite(&machine_code_address, sizeof(long), 1, pFile);
            fwrite(&machine_code_size, sizeof(long), 1, pFile);
            uint8_t buffer[machine_code_line.size()+1];
            
            buffer[0]= (uint8_t)232;
            for (unsigned i=0; i<machine_code_line.size(); i++){
               buffer[i+1] = machine_code_line[i];
            }
            fwrite (buffer , sizeof(uint8_t), machine_code_line.size()+1, pFile);
         }  
      }
#endif
#ifdef AArch64
      if (call_sites_list.find(it->first)!=call_sites_list.end()){
         vector<long> caller_lists = call_sites_list[it->first];
         for (unsigned i=0; i<caller_lists.size(); i++){
            long addr = caller_lists[i];
            long belonged_func = call_sites[addr].belonged_func;
            if (func_in_call_stack.find(belonged_func)==func_in_call_stack.end()) continue;
            long new_target_addr = it->second.moved_addr;
            uint32_t machine_code=compute_bl_instruction((uint32_t)new_target_addr, (uint32_t)addr);
            vector<uint8_t> machine_code_line=convert_uint32_2_vec_uint8(machine_code);

            // write the virtual address + the size of the machine code
            // and machine code itself into a file
            long machine_code_address = addr;
            long machine_code_size = (long)(machine_code_line.size());
            fwrite(&machine_code_address, sizeof(long), 1, pFile);
            fwrite(&machine_code_size, sizeof(long), 1, pFile);
            uint8_t buffer[machine_code_line.size()];
            int lens=machine_code_line.size();
            //cout<<"machine_code_address:"<<std::hex<<machine_code_address<<",machine_code_size:"<<machine_code_size<<",machine_code_line:"<<std::hex;
            for (unsigned i=0; i<machine_code_line.size(); i++){
               buffer[i] = machine_code_line[lens-1-i];
            //   cout << hex << setw(2) << setfill('0') << static_cast<unsigned>(machine_code_line[i])<<" ";
            }
            //cout<<endl;
            fwrite (buffer , sizeof(uint8_t), machine_code_line.size(), pFile);
         }  
      }
#endif
   }
}


// in libelf_extract.a
extern "C" {
  /*
   * Invoke Rust code to extract functions from the given 
   * binary. The starting addresses of functions to be 
   * extracted are passed by an array of long integers.
   */
   void write_functions(const char* bolted_binary_path, const char* vtable_output_file_path, long* function_addrs, long num_addrs);



  /*
   * Invoke Rust code to extract v-tables from the given
   * binary. The arguments are the path of the binary that
   * will have data extracted, and the path to store the 
   * extracted data.
   */ 
   void write_vtable(const char*, const char*);
}
