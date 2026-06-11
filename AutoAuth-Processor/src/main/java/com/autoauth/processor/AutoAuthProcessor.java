package com.autoauth.processor;

import com.autoauth.processor.annotation.EnableAutoAuth;
import com.google.auto.service.AutoService;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.TypeSpec;

import javax.annotation.processing.*;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import java.io.IOException;
import java.util.Set;

@AutoService(Processor.class)
@SupportedAnnotationTypes("com.autoauth.processor.annotation.EnableAutoAuth")
public class AutoAuthProcessor extends AbstractProcessor {

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latestSupported();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {

        for (Element element : roundEnv.getElementsAnnotatedWith(EnableAutoAuth.class)) {

            processingEnv.getMessager().printMessage(
                    javax.tools.Diagnostic.Kind.NOTE,
                    "AutoAuth: Found @EnableAutoAuth on " + element.getSimpleName() + ". Generating code..."
            );

            generateDummyFilterClass();
        }

        return true;
    }

    private void generateDummyFilterClass() {
        try {
            MethodSpec constructor = MethodSpec.constructorBuilder()
                    .addModifiers(Modifier.PUBLIC)
                    .addStatement("$T.out.println($S)", System.class, "AutoAuth Generated Filter Boots Up!")
                    .build();

            TypeSpec filterClass = TypeSpec.classBuilder("GeneratedJwtFilter")
                    .addModifiers(Modifier.PUBLIC)
                    .addMethod(constructor)
                    .build();

            JavaFile javaFile = JavaFile.builder("com.autoauth.generated", filterClass)
                    .build();

            javaFile.writeTo(processingEnv.getFiler());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}