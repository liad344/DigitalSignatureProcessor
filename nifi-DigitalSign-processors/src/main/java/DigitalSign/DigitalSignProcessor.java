/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package DigitalSign;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.io.StreamCallback;
import org.apache.nifi.processor.util.StandardValidators;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Tags({"example"})
@CapabilityDescription("Provide a description")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class DigitalSignProcessor extends AbstractProcessor {

    final int bufferSize = 16*1000*1000;
    public static final PropertyDescriptor KeyPath = new PropertyDescriptor
            .Builder().name("KeyPath")
            .displayName("Key path")
            .description("C:\\keys")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor PassThroughLen = new PropertyDescriptor
            .Builder().name("PassThroughLen")
            .displayName("\"PassThroughLen")
            .description("\"PassThroughLen")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();
    public static final PropertyDescriptor RouteId = new PropertyDescriptor
            .Builder().name("RouteId")
            .displayName("RouteId")
            .description("23")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final Relationship VALID_SIGNATURE = new Relationship.Builder()
            .name("Valid")
            .description("Hash was confirmed")
            .build();
    public static final Relationship NON_VALID_SIGNATURE = new Relationship.Builder()
            .name("Non Valid")
            .description("Stupid ass nigga hacker")
            .build();
    public static final Relationship FAILURE = new Relationship.Builder()
            .name("Failure ")
            .description("Stupid ass nigga Something broke")
            .build();
    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(KeyPath);
        descriptors.add(RouteId);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<Relationship>();
        relationships.add(VALID_SIGNATURE);
        relationships.add(NON_VALID_SIGNATURE);
        relationships.add(FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {

    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if ( flowFile == null ) {
            return;
        }
        InputStream inputStream = session.read(flowFile);
        try {
            Validate(context, session, flowFile, inputStream);
        }
        catch (Exception e) {
            session.transfer(flowFile , FAILURE );
        }
    }

    private void Validate(ProcessContext context, ProcessSession session, FlowFile flowFile, InputStream inputStream) throws NoSuchAlgorithmException, IOException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] key = getKeyFromFile(context);
        byte[] encryptedHash = getEncryptedHash(session, flowFile, inputStream);
        byte[] iv = getIV(session, flowFile, inputStream);
        byte[] decryptedHash = decryptedAes(encryptedHash , key , session, iv);
        if (decryptedHash != null) {
            byte[] fileHash = hashFile(inputStream , md);
            if (Arrays.equals(decryptedHash , fileHash)){
                InputStream newStream = session.read(flowFile);
                FlowFile newff = session.create();
                OutputStream newFileOutStream = session.write(newff);
                removeHash(flowFile , newStream , session , newFileOutStream) ;
                session.transfer( newff , VALID_SIGNATURE);
            }
        }
        inputStream.close();
        session.transfer(flowFile , NON_VALID_SIGNATURE);
    }

    private void removeHash(FlowFile flowFile, InputStream newStream, ProcessSession session, OutputStream newFileOutStream) throws IOException {
        int trimmedSize = (int) (flowFile.getSize() - 80);
            int pointer = 0;
            while (pointer != trimmedSize) {
                int leftToRead = trimmedSize % bufferSize;
                byte[] data;
                if (leftToRead == 0) {
                    data = newStream.readNBytes(bufferSize);
                    pointer += bufferSize;
                } else {
                    data = newStream.readNBytes(leftToRead);
                    pointer += leftToRead;
                }
                newFileOutStream.write(data);
            }
    }

        private byte[] getEncryptedHash(ProcessSession session, FlowFile flowFile, InputStream inputStream) throws IOException {
        byte[] encryptedHash = new byte[64];
        int n = inputStream.readNBytes(encryptedHash , Math.toIntExact(flowFile.getSize()) - 64 , 64);
        if (n != 64){
            session.transfer(flowFile , FAILURE);
        }
        return encryptedHash ;
    }
    private byte[] getIV(ProcessSession session, FlowFile flowFile, InputStream inputStream) throws IOException {
        byte[] iv = new byte[16];
        int n = inputStream.readNBytes(iv , Math.toIntExact(flowFile.getSize()) - 64 , 64);
        if (n != 16){
            session.transfer(flowFile , FAILURE);
        }
        return iv ;
    }

    private byte[] getKeyFromFile(ProcessContext context) throws IOException {
        String keyPath = context.getProperty(KeyPath).toString();
        String route = context.getProperty(RouteId).toString();
        Path filePath = Paths.get(keyPath, route , "key.txt");
        RandomAccessFile f = new RandomAccessFile(String.valueOf(filePath), "r");
        byte[] keyData = new byte[16];
        f.readFully(keyData);
        return keyData;
    }
    private byte[] hashFile(InputStream readStream, MessageDigest md) throws IOException {
        boolean eof = false;
        while (!eof) {
            byte[] data = readStream.readNBytes(bufferSize);
            if (data.length != 0) {
                md.update(data);
            } else {
                eof = true;
            }
        }
        return md.digest();
    }
    private byte[] decryptedAes(byte[] encryptedHash, byte[] key, ProcessSession session, byte[] ivBytes) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey , iv);
            return cipher.doFinal(encryptedHash);
        }
        catch (Exception e){
            return null;
        }

    }
}
