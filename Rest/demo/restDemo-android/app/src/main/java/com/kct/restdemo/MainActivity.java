package com.kct.restdemo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.kct.restdemo.rest.RestHttpClient;

public class MainActivity extends AppCompatActivity {

    public String sid = "b64e977c108810429b9056208059d362";
    public String token = "cd1e4ce88775dcaf8bbf9236e9811c4a";
    public String appid = "57993353d8724285904ba22a20d51ee9";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        new Thread(new Runnable() {
            @Override
            public void run() {
                RestHttpClient mRestHttpClient = new RestHttpClient();
                String json = mRestHttpClient.applySdkId(sid, token, appid);
                Log.e("KC", json);
            }
        }).start();
    }
}
