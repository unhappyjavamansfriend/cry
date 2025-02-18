package com.feddoubt.model.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
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
