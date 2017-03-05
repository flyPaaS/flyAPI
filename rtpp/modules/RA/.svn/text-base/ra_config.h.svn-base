#ifndef _RA_CONFIG_H_
#define _RA_CONFIG_H_

#include <string>
#include <list>
#include <map>
#include <sstream>
#include <iostream>
#include <pthread.h>
#include <assert.h>

#include "common.h"


class noncopyable
{
	protected:
		noncopyable() {}
		~noncopyable() {}
	private:
		noncopyable(const noncopyable&);
		noncopyable& operator=(const noncopyable&);
};
class MutexLock : private noncopyable
{
	public:
		MutexLock()
		{
			assert(0 == pthread_mutex_init(&mutex_, NULL));
		}
		~MutexLock()
		{
			assert(0 == pthread_mutex_destroy(&mutex_));
		}

		void lock()
		{
			assert(0 == pthread_mutex_lock(&mutex_));
		}

		void unlock()
		{
			assert(0 == pthread_mutex_unlock(&mutex_));
		}
	private:
		pthread_mutex_t mutex_;

}; //class MutexLock

class MutexLockGuard : private noncopyable
{

	public:
		explicit MutexLockGuard(MutexLock& mutex)
					: mutex_(mutex)
		{
			mutex_.lock();
		}

		~MutexLockGuard()
		{
			mutex_.unlock();
		}
	private:
		MutexLock& mutex_;
};//class MutexLockGuard

class Lock  {
    private:
        pthread_mutex_t m_lock;
    public:
        Lock(pthread_mutex_t  cs) : m_lock(cs) {
            pthread_mutex_lock(&m_lock);
        }
        ~Lock() {
            pthread_mutex_unlock(&m_lock);
        }
};


class ConfigFile {

private:
	ConfigFile();
	ConfigFile(const ConfigFile &);
	ConfigFile& operator = (const ConfigFile &);
		
	std::map<std::string,std::string> datamap;
	std::string filename;
	

public:
	bool load(std::string filename);
	static pthread_mutex_t  mutex;

	~ConfigFile();

	static ConfigFile *pInstance;

	void dump(void);

	static ConfigFile *GetInstance();

	template < typename T>
	T getvalue(std::string key) {
		std::string str = datamap[key];
		if (str=="") {
			std::cerr << "WARNING: '" << key <<"' was not defined in " << filename << "! Value is undefined!" << std::endl;
		}
		std::stringstream ss;
		ss << str;
		T value;
		ss >> value;
		return value;	
	}

	template < typename T>
	T getvalue(std::string key, T defaultValue) {
		std::string str = datamap[key];
		if (str=="") {
			return defaultValue;
		}
		return getvalue<T>(key);
	}

	template < typename T>
	T getvalueidx(std::string key,int idx, T defaultValue) {
		std::stringstream ss;
		ss << idx;
			std::string query=key+std::string("[")+ss.str()+std::string("]");
		return getvalue<T>(query,defaultValue);
	}

	template < typename T>
	T getvalueidx(std::string key,int idx) {
		std::stringstream ss;
		ss << idx;
		std::string query=key+std::string("[")+ss.str()+std::string("]");
		return getvalue<T>(query);
	}
};



#endif
