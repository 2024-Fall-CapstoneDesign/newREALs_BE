package newREALs.backend.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import newREALs.backend.config.ChatGPTConfig;
import newREALs.backend.dto.GptRequestDto;
import newREALs.backend.dto.GptResponseDto;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;


@Service
public class ChatGPTServiceImpl implements ChatGPTService {
    private final RestTemplate restTemplate;
    private final HttpHeaders headers;
    private final String model = "gpt-3.5-turbo"; // 최신 모델로 변경

    public ChatGPTServiceImpl(ChatGPTConfig chatGPTConfig) {
        this.restTemplate = chatGPTConfig.restTemplate();
        this.headers = chatGPTConfig.httpHeaders();
    }

    @Override
    public Map<String, Object> generateContent(List<Map<String,String>> messages) {

        // GptRequestDto에 messages 필드 전달
        GptRequestDto requestDto = GptRequestDto.builder()
                .model(model)
                .messages(messages)
                .temperature(0.7f)
                .max_tokens(1000)
                .build();

        HttpEntity<GptRequestDto> entity = new HttpEntity<>(requestDto, headers);

        // 최신 엔드포인트 URL 사용
        String url = "https://api.openai.com/v1/chat/completions";
        ResponseEntity<GptResponseDto> response = restTemplate.postForEntity(url, entity, GptResponseDto.class);

        try {
            // ObjectMapper를 사용하여 응답을 파싱합니다.
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> result = objectMapper.convertValue(response.getBody(), new TypeReference<>() {});

            // "choices"에서 첫 번째 응답의 "message" 항목을 가져옵니다.
            List<Map<String, Object>> choices = (List<Map<String, Object>>) result.get("choices");
            Map<String, Object> message = (Map<String, Object>) choices.get(0).get("message");
            String text = (String) message.get("content");

            return Map.of("text", text); // 반환값을 Map으로 래핑하여 반환
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse response from GPT", e);
        }
    }
}
