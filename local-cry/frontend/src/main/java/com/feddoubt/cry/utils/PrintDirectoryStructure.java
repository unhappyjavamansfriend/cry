package com.feddoubt.cry.utils;

import java.io.File;

public class PrintDirectoryStructure {
    private static final String LINE_PREFIX = "│   ";
    private static final String LAST_LINE_PREFIX = "    ";
    private static final String BRANCH = "├── ";
    private static final String LAST_BRANCH = "└── ";

    public static void main(String[] args) {
        String rootPath = "D:\\local\\workspace\\cry\\nginx";
        File rootDir = new File(rootPath);

        // Print root directory
        System.out.println(rootPath);
        printFileTree(rootDir, "", true);
    }

    private static void printFileTree(File file, String prefix, boolean isRoot) {
        File[] files = file.listFiles();
        if (files == null || files.length == 0) return;

        for (int i = 0; i < files.length; i++) {
            boolean isLast = (i == files.length - 1);

            // Don't print prefix for root level
            if (!isRoot) {
                System.out.print(prefix);
                System.out.print(isLast ? LAST_BRANCH : BRANCH);
            }

            System.out.println(files[i].getName() + (files[i].isDirectory() ? "/" : ""));

            if (files[i].isDirectory()) {
                String newPrefix = prefix;
                if (!isRoot) {
                    newPrefix += isLast ? LAST_LINE_PREFIX : LINE_PREFIX;
                }
                printFileTree(files[i], newPrefix, false);
            }
        }
    }
}