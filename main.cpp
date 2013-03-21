#include <WINDOWS.H>    
#include <STDIO.H>    
#include <WINNT.H> 
  
BOOL ReadOEPbyFile(LPCSTR szFileName);   
BOOL WINAPI DelFileBySectionName(LPCSTR szFileName, char *szSection);
//char dec2hex(int n);
int sectionNum(LPVOID lpBase,DWORD VirtualAddress) ;
//DeleteFile( LPCSTR filename ); 
int main()   
{   
    ReadOEPbyFile("test.dll"); 
    bool delfile = DelFileBySectionName("test.dll",".xx32");   
    
    if (delfile) 
    {
      remove( "test.dll");
      system( "del   test.dll "); 
    }
    system("PAUSE");	
    return 0;
}
   
// 通过文件读取OEP值.    
BOOL ReadOEPbyFile(LPCSTR szFileName)   
{   
    HANDLE hFile;   
       
    // 打开文件.    
    if ((hFile = CreateFile(szFileName, GENERIC_READ,   
        FILE_SHARE_READ, 0, OPEN_EXISTING,    
        FILE_FLAG_SEQUENTIAL_SCAN, 0)) == INVALID_HANDLE_VALUE)   
    {   
        printf("can't open file by File.\n");   
        return FALSE;   
    }   
       
    DWORD dwOEP,cbRead;   
    IMAGE_DOS_HEADER dos_head[sizeof(IMAGE_DOS_HEADER)];   
    if (!ReadFile(hFile, dos_head, sizeof(IMAGE_DOS_HEADER), &cbRead, NULL)){    
        printf("read image_dos_header failed.\n");   
        CloseHandle(hFile);   
        return FALSE;   
    }   
       
    int nEntryPos=dos_head->e_lfanew+40;   
    SetFilePointer(hFile, nEntryPos, NULL, FILE_BEGIN);   
       
    if (!ReadFile(hFile, &dwOEP, sizeof(dwOEP), &cbRead, NULL)){    
        printf("read OEP failed.\n");   
        CloseHandle(hFile);   
        return FALSE;   
    }   
       
    // 关闭文件.    
    CloseHandle(hFile);   
       
    // 显示OEP地址.    
    printf("OEP by file:0x%x\n",dwOEP);  
    return TRUE;   
}   
   
//若OEP（AddressOfEntryPoint）在这个节的范围内，则删除该文件
BOOL WINAPI DelFileBySectionName(LPCSTR szFileName, char *szSection)
{
    struct PE_HEADER_MAP   
    {   
        DWORD signature;   
        IMAGE_FILE_HEADER _head;   
        IMAGE_OPTIONAL_HEADER opt_head;   
        IMAGE_SECTION_HEADER section_header[6];   
    } *header;   
   
    HANDLE hFile;   
    HANDLE hMapping;   
    LPVOID lpBase;   
       
    // 打开文件.    
    if ((hFile = CreateFile(szFileName, GENERIC_READ,   
        FILE_SHARE_READ,0,OPEN_EXISTING,    
        FILE_FLAG_SEQUENTIAL_SCAN,0)) == INVALID_HANDLE_VALUE)   
    {   
        printf("can't open file by Memory.\n");  
        return FALSE;   
    }   
       
    // 创建内存映射文件.    
    if (!(hMapping = CreateFileMapping(hFile,0,PAGE_READONLY|SEC_COMMIT,0,0,0)))   
    {   
        printf("mapping failed\n");   
        CloseHandle(hFile);   
        return FALSE;   
    }   
       
    // 把文件头映象存入baseointer.    
    if (!(lpBase = MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0)))   
    {   
        printf("view failed.\n");   
        CloseHandle(hMapping);   
        CloseHandle(hFile);   
        return FALSE;   
    }   
    IMAGE_DOS_HEADER * dos_header =(IMAGE_DOS_HEADER *)lpBase; 
      
    if (dos_header->e_magic!=IMAGE_DOS_SIGNATURE)  
    {  
       printf("This is not a windows file\n");  
       return FALSE;  
    }
    // 得到PE文件头.    
    header = (PE_HEADER_MAP *)((char *)dos_header+dos_header->e_lfanew);     
    // 得到OEP地址.    
    DWORD dwOEP=header->opt_head.AddressOfEntryPoint;   
    printf("OEP by memory:0x%x\n",dwOEP); 
       
       IMAGE_NT_HEADERS *ntHeader;
       int NumOfSections;

       // 找到PE头在文件中的偏移地址
       ntHeader=(IMAGE_NT_HEADERS*)((BYTE*)lpBase+dos_header->e_lfanew); 
       // 获得PE文件中“段”的数量
       NumOfSections=ntHeader->FileHeader.NumberOfSections;  
       int ncout=sectionNum(lpBase,ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);  
        if(ncout==-1)  
        {  
           printf("get section failed\n");  
           return 0;  
        } 
         
        IMAGE_SECTION_HEADER *sectionHeader;  
        // 获得”段“的头信息
        sectionHeader=(IMAGE_SECTION_HEADER*)((BYTE*)lpBase+dos_header->e_lfanew+sizeof(IMAGE_NT_HEADERS))+ncout; 

        for (;ncout < NumOfSections;ncout++)
        {
             
            if (!strcmp((char*)sectionHeader->Name,szSection)) { 
            // 比较OEP和“段”的虚拟地址（起始和结束地址）
              if(header->opt_head.AddressOfEntryPoint>=sectionHeader->VirtualAddress &&
                 header->opt_head.AddressOfEntryPoint<sectionHeader->VirtualAddress+sectionHeader->SizeOfRawData)
                 {
                   printf("发现木马文件%s然后删除\n", szFileName);
     
                  // if (!::DeleteFile(szFileName))
                  //printf("删除文件%s失败\n", szFileName);
                   break;
                 }
            }
             sectionHeader++;    
        }
    if(ncout<NumOfSections) {
        return true;     
    }
    else  {
           printf("未发现木马文件\n");
           return FALSE; 
          }
}

/*
char dec2hex(int n)  // 十进制转十六进制 
{	      
     if(n == 0)		                 
     return 0;	            
     dec2hex(n/16);	             
      int m = n % 16;	            
      return char(m + (m< 10 ? '0' : 'A' - 10));
}
*/
int sectionNum(LPVOID lpBase,DWORD VirtualAddress)  
{  
    IMAGE_DOS_HEADER *dosHeader;  
    IMAGE_NT_HEADERS *ntHeader;  
    IMAGE_SECTION_HEADER *sectionHeader;  
    int NumOfSections;  
    dosHeader=(IMAGE_DOS_HEADER*)lpBase;  
    ntHeader=(IMAGE_NT_HEADERS*)((BYTE*)lpBase+dosHeader->e_lfanew);  
    NumOfSections=ntHeader->FileHeader.NumberOfSections;  
    for (int i=0;i<NumOfSections;i++)  
    {  
      sectionHeader=(IMAGE_SECTION_HEADER*)((BYTE*)lpBase+dosHeader->e_lfanew+sizeof(IMAGE_NT_HEADERS))+i;  
      if(VirtualAddress>sectionHeader->VirtualAddress && 
       VirtualAddress<sectionHeader->VirtualAddress+sectionHeader->SizeOfRawData)  
      {  
         return i;  
      }  
    }  
    return -1;  
}  

