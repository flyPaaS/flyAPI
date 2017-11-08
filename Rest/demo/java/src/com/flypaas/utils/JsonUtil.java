package com.flypaas.utils;

import com.google.gson.Gson;

public class JsonUtil {
	public static String toJsonStr(Object obj) {
		Gson gson = new Gson();
		return gson.toJson(obj);
	}
}
