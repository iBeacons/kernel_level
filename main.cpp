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
   
// ͨ���ļ���ȡOEPֵ.    
BOOL ReadOEPbyFile(LPCSTR szFileName)   
{   
    HANDLE hFile;   
       
    // ���ļ�.    
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
       
    // �ر��ļ�.    
    CloseHandle(hFile);   
       
    // ��ʾOEP��ַ.    
    printf("OEP by file:0x%x\n",dwOEP);  
    return TRUE;   
}   
   
//��OEP��AddressOfEntryPoint��������ڵķ�Χ�ڣ���ɾ�����ļ�
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
       
    // ���ļ�.    
    if ((hFile = CreateFile(szFileName, GENERIC_READ,   
        FILE_SHARE_READ,0,OPEN_EXISTING,    
        FILE_FLAG_SEQUENTIAL_SCAN,0)) == INVALID_HANDLE_VALUE)   
    {   
        printf("can't open file by Memory.\n");  
        return FALSE;   
    }   
       
    // �����ڴ�ӳ���ļ�.    
    if (!(hMapping = CreateFileMapping(hFile,0,PAGE_READONLY|SEC_COMMIT,0,0,0)))   
    {   
        printf("mapping failed\n");   
        CloseHandle(hFile);   
        return FALSE;   
    }   
       
    // ���ļ�ͷӳ�����baseointer.    
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
    // �õ�PE�ļ�ͷ.    
    header = (PE_HEADER_MAP *)((char *)dos_header+dos_header->e_lfanew);     
    // �õ�OEP��ַ.    
    DWORD dwOEP=header->opt_head.AddressOfEntryPoint;   
    printf("OEP by memory:0x%x\n",dwOEP); 
       
       IMAGE_NT_HEADERS *ntHeader;
       int NumOfSections;

       // �ҵ�PEͷ���ļ��е�ƫ�Ƶ�ַ
       ntHeader=(IMAGE_NT_HEADERS*)((BYTE*)lpBase+dos_header->e_lfanew); 
       // ���PE�ļ��С��Ρ�������
       NumOfSections=ntHeader->FileHeader.NumberOfSections;  
       int ncout=sectionNum(lpBase,ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);  
        if(ncout==-1)  
        {  
           printf("get section failed\n");  
           return 0;  
        } 
         
        IMAGE_SECTION_HEADER *sectionHeader;  
        // ��á��Ρ���ͷ��Ϣ
        sectionHeader=(IMAGE_SECTION_HEADER*)((BYTE*)lpBase+dos_header->e_lfanew+sizeof(IMAGE_NT_HEADERS))+ncout; 

        for (;ncout < NumOfSections;ncout++)
        {
             
            if (!strcmp((char*)sectionHeader->Name,szSection)) { 
            // �Ƚ�OEP�͡��Ρ��������ַ����ʼ�ͽ�����ַ��
              if(header->opt_head.AddressOfEntryPoint>=sectionHeader->VirtualAddress &&
                 header->opt_head.AddressOfEntryPoint<sectionHeader->VirtualAddress+sectionHeader->SizeOfRawData)
                 {
                   printf("����ľ���ļ�%sȻ��ɾ��\n", szFileName);
     
                  // if (!::DeleteFile(szFileName))
                  //printf("ɾ���ļ�%sʧ��\n", szFileName);
                   break;
                 }
            }
             sectionHeader++;    
        }
    if(ncout<NumOfSections) {
        return true;     
    }
    else  {
           printf("δ����ľ���ļ�\n");
           return FALSE; 
          }
}

/*
char dec2hex(int n)  // ʮ����תʮ������ 
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

