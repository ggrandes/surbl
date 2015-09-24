# SURBL

Java Client Library for SURBL - Spam URI Real-time Blackhole List. Open Source Java project under Apache License v2.0

### Current Stable Version is [1.0.0](https://search.maven.org/#search|ga|1|g%3Aorg.javastack%20a%3Asurbl)

---

## DOC

#### Usage Example

```java
import org.javastack.surbl.SURBL;

public class Example {
	public static void main(String[] args) throws Throwable {
		final SURBL surbl = new SURBL();
		surbl.load();
		System.out.println(surbl.checkSURBL("www.acme.com") ? "spam" : "clean");
	}
}
```

* More examples in [Example package](https://github.com/ggrandes/surbl/tree/master/src/main/java/org/javastack/surbl/example/)

---

## MAVEN

Add the dependency to your pom.xml:

    <dependency>
        <groupId>org.javastack</groupId>
        <artifactId>surbl</artifactId>
        <version>1.0.0</version>
    </dependency>

---
Inspired in [SURBL](http://www.surbl.org/), this code is Java-minimalistic version.
