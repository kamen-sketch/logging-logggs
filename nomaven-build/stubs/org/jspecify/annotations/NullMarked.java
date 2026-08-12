package org.jspecify.annotations;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS)
@Target({ElementType.MODULE, ElementType.PACKAGE, ElementType.TYPE, ElementType.METHOD, ElementType.CONSTRUCTOR, ElementType.FIELD})
public @interface NullMarked {}
