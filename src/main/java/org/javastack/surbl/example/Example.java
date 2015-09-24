package org.javastack.surbl.example;

import org.javastack.surbl.SURBL;

public class Example {
	public static void main(String[] args) throws Throwable {
		final SURBL surbl = new SURBL();
		surbl.load();
		System.out.println(surbl.checkSURBL("www.acme.com") ? "spam" : "clean");
	}
}
