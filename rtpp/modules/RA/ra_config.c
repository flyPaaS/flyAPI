#include <fstream>
#include "ra_config.h"

using namespace std;

pthread_mutex_t  ConfigFile::mutex = PTHREAD_MUTEX_INITIALIZER;
ConfigFile* ConfigFile::pInstance = NULL;

void str2lower(string &str) {
	for(unsigned int i=0;i<str.size();i++)
	{
		str[i] = tolower(str[i]);
	}
}
std::string trim(std::string const& source, char const* delims = " \t\r\n") {
  std::string result(source);
  std::string::size_type index = result.find_last_not_of(delims);
  if(index != std::string::npos)
    result.erase(++index);

  index = result.find_first_not_of(delims);
  if(index != std::string::npos)
    result.erase(0, index);
  else
    result.erase();
  return result;
}

 OSAL_INT32 creatRaDefaultConf()
{
	FILE *filestream;

	filestream  = fopen(RA_CFG_FILE ,"w+");
	if(filestream == OSAL_NULL) {
		 printf("complete cfg file err:%s.", strerror(errno));
		 return OSAL_ERROR;
	}

	fputs("#router configuration\n", filestream);
	fputs("ROUTER_LIST = 59.110.10.28:9955/192.168.0.10:9955\n", filestream);
	fputs("\n", filestream);
	fputs("#Agent configuration.Be used to register to router\n", filestream);
	fputs("AGENT_ADDR = 192.168.0.127\n", filestream);
	fputs("AGENT_ADDR_BAK = 192.168.0.127\n", filestream);
	fputs("\n", filestream);
	fputs("#Ping configuration\n", filestream);
	fputs("#The time interval(ms) of sending ping packet\n", filestream);
	fputs("PING_PKT_INTERVAL = 500\n", filestream);
	fputs("#The time interval(s) of calculating ping result\n", filestream);
	fputs("PING_CALC_INTERVAL = 5\n", filestream);
	
	fclose(filestream);
	return OSAL_OK;
}

ConfigFile::ConfigFile() {
	filename = RA_CFG_FILE;
	
	if(access(RA_CFG_FILE, F_OK)) {  //not exsited
		if(OSAL_OK != creatRaDefaultConf()){
			OSAL_trace(eRTPP, eSys,"create ra default conf failed!");
			exit(-1);
		}
	}
	if(!load(filename))
	{
		//cerr << "Configfile '" << filename << "' not found!" << endl;
		OSAL_trace(eRTPP, eSys,"Configfile: %s not fund!!!", filename.c_str());
		exit(-1);
	}
}


ConfigFile *ConfigFile::GetInstance(){   
    if(pInstance == NULL)   {   
	//MutexLockGuard lock(mutex_);
		Lock lock(mutex);  
        if(pInstance == NULL)   {   
            pInstance = new ConfigFile();
        }   
    }   
    return pInstance;
}

bool ConfigFile::load(string filename) {
	this->filename=filename;
	fstream f;
	f.open(filename.c_str(),fstream::in);
	if (!f.is_open())	{
		return false;
	}
	string line;
	int lnr=-1;
	while (getline(f,line))	{
		lnr++;
		//Skip Comments and empty lines
		if (! line.length()) continue;
	    if (line[0] == '#') continue;
    	if (line[0] == ';') continue;

		int posTrenner=line.find('=');
		if (posTrenner==-1)
			posTrenner=line.find(' ');
		if (posTrenner==-1) {
			cerr << "WARNING: Statement '" << line << "' in file "<< filename << ":"<<lnr<<" is invalid and therefor will be ignored" << endl;
			continue;
		}
		string key=trim(line.substr(0,posTrenner));
		string value=trim(line.substr(posTrenner+1));

		//Case insensitive
		str2lower(key);

		if (datamap[key]!="") {
			cerr << "WARNING: Statement '" << line << "' in file "<< filename << ":"<<lnr<<" redefines a value!" << endl;
		}
		datamap[key]=value;
	 }
	f.close();
	return true;
}

void ConfigFile::dump(void) {
	for (map<string,string>::iterator iter= datamap.begin(); iter!=datamap.end();iter++){
		cout << iter->first << " = " << iter->second << endl;
	}
}

ConfigFile::~ConfigFile() {
}


