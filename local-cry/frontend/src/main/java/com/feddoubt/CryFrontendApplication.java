package com.feddoubt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
//@EnableDiscoveryClient
public class CryFrontendApplication
{
    public static void main( String[] args )
    {
        SpringApplication.run(CryFrontendApplication.class ,args);
    }
}
