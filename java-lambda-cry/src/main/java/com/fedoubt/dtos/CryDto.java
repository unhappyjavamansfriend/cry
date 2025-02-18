package com.fedoubt.dtos;

import lombok.Data;

import java.util.Arrays;
import java.util.List;

@Data
public class CryDto {
    String itemname;
    String username;
    String password;
    public List<String> getDataList() {
        return Arrays.asList(this.itemname, this.username, this.password);
    }
}
