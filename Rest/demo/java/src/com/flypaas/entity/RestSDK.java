package com.flypaas.entity;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlRootElement;
@XmlRootElement(name = "SDK")
public class RestSDK implements Serializable{
	private static final long serialVersionUID = -5201763125501406865L;
	
	private String appId;

	public String getAppId() {
		return appId;
	}

	public void setAppId(String appId) {
		this.appId = appId;
	}
	
}
