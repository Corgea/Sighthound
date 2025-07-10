package com.example.insecurejava;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.thoughtworks.xstream.XStream;

@RestController
public class OtherDeserializationVulns {
    
    @PostMapping("/xmlDecode")
    public String xmlDeserialize(@RequestBody String xmlData) {
        // This should trigger XMLDecoder rule
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlData.getBytes()));
        Object result = decoder.readObject();
        return result.toString();
    }
    
    @PostMapping("/jackson")
    public String jacksonDeserialize(@RequestBody String jsonData) throws Exception {
        // This should trigger Jackson rule
        ObjectMapper mapper = new ObjectMapper();
        Object result = mapper.readValue(jsonData, Object.class);
        return result.toString();
    }
    
    @PostMapping("/gson")
    public String gsonDeserialize(@RequestBody String jsonData) {
        // This should trigger Gson rule
        Gson gson = new Gson();
        Object result = gson.fromJson(jsonData, Object.class);
        return result.toString();
    }
    
    @PostMapping("/xstream")
    public String xstreamDeserialize(@RequestBody String xmlData) {
        // This should trigger XStream rule
        XStream xstream = new XStream();
        Object result = xstream.fromXML(xmlData);
        return result.toString();
    }
} 