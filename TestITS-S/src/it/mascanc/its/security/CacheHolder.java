package it.mascanc.its.security;
//package it.autostrade.its.security;
//
//import java.util.HashMap;
//
//
//public class CacheHolder {
//	private static volatile CacheHolder instance;
//	private HashMap<String, Object> cache = new HashMap<String, Object>();
//
//	private CacheHolder() {
//
//		// Private constructor prevents instantiation by untrusted callers
//	}
//
//	// Double-checked locking
//	public static CacheHolder getInstance() {
//		if (instance == null) {
//			synchronized (CacheHolder.class) {
//				if (instance == null) {
//					instance = new CacheHolder();
//				}
//			}
//		}
//		return instance;
//	}
//	
//	public void add(String key, Object obj) {
//		this.cache.put(key, obj);
//	}
//	
//	public Object get(String key) throws InterruptedException {
//		Object back = cache.get(key);
//		if (back == null) {
//			System.out.println("La chiave " + key + " non c'è ancora. Riprovo");
//			Thread.sleep(100);
//			return get(key);
//		} else {
//			return back;
//		}
//	}
//}
