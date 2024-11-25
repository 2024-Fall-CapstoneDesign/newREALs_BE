package newREALs.backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import newREALs.backend.domain.Accounts;
import newREALs.backend.repository.UserKeywordRepository;
import newREALs.backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@SuppressWarnings("unchecked")
@Service
@RequiredArgsConstructor
public class

KakaoService {
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final RestTemplate restTemplate = new RestTemplate();
    private final UserKeywordRepository userKeywordRepository;

    // applications.yml에서 값 가져오기
    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.kakao.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.provider.kakao.user-info-uri}")
    private String userInfoUri;

//    public Map<String, Object> processKakaoLogin(String authorizationCode) {
//        String kakaoAccessToken = getAccessToken(authorizationCode);
//        Map<String, Object> userInfo = getUserInfo(kakaoAccessToken);
//
//        String providerId = userInfo.get("id").toString();
//        String email = (String) ((Map<String, Object>) userInfo.get("kakao_account")).get("email");
//        String name = (String) ((Map<String, Object>) userInfo.get("properties")).get("name");
//        String profilePath = (String) ((Map<String, Object>) userInfo.get("properties")).get("profile_image");
//
//        Optional<Accounts> optionalAccount = userRepository.findByProviderId(providerId);
//        Map<String, Object> response = new HashMap<>();
//
//        if (optionalAccount.isEmpty()) {
//            Accounts newAccount = userRepository.save(
//                    Accounts.builder()
//                            .providerId(providerId)
//                            .email(email)
//                            .name(name)
//                            .profilePath(profilePath)
//                            .build()
//            );
//
//            String temporaryToken = tokenService.generateTemporaryToken(providerId);
//            response.put("temporaryToken", temporaryToken);
//            response.put("redirectUrl", "/register");
//            response.put("isNewAccount", true);
//            response.put("name", newAccount.getName());
//            response.put("email", newAccount.getEmail());
//            response.put("userId", newAccount.getId());
//        } else {
//            Accounts account = optionalAccount.get();
//            boolean hasKeywords = userKeywordRepository.existsByUserId(account.getId());
//
//            if(!hasKeywords) {
//                String temporaryToken = tokenService.generateTemporaryToken(providerId);
//                response.put("temporaryToken", temporaryToken);
//                response.put("redirectUrl", "/register");
//            } else {
//                String accessToken = tokenService.generateAccessToken(account);
//                String refreshToken = tokenService.generateRefreshToken(account);
//                response.put("accessToken", accessToken);
//                response.put("refreshToken", refreshToken);
//                response.put("redirectUrl", "/home");
//            }
//            response.put("name", account.getName());
//            response.put("email", account.getEmail());
//            response.put("profilePath", account.getProfilePath());
//        }
//        return response;
//    }
public Map<String, Object> processKakaoLogin(String authorizationCode) {
    String kakaoAccessToken = getAccessToken(authorizationCode);
    Map<String, Object> userInfo = getUserInfo(kakaoAccessToken);

    String providerId = Optional.ofNullable(userInfo.get("id"))
            .map(Object::toString)
            .orElseThrow(() -> new IllegalArgumentException("Provider ID가 없습니다."));
    String email = Optional.ofNullable((String) ((Map<String, Object>) userInfo.get("kakao_account")).get("email"))
            .orElseThrow(() -> new IllegalArgumentException("이메일 정보가 없습니다."));
    String name = Optional.ofNullable((String) ((Map<String, Object>) userInfo.get("properties")).get("nickname"))
            .orElseThrow(() -> new IllegalArgumentException("이름 정보가 없습니다."));
    String profilePath = (String) ((Map<String, Object>) userInfo.get("properties")).get("profile_image");

    Optional<Accounts> optionalAccount = userRepository.findByProviderId(providerId);
    Map<String, Object> response = new HashMap<>();

    if (optionalAccount.isEmpty()) {
        Accounts newAccount = userRepository.save(
                Accounts.builder()
                        .providerId(providerId)
                        .email(email)
                        .name(name)
                        .profilePath(profilePath)
                        .build()
        );

        String temporaryToken = tokenService.generateTemporaryToken(providerId);
        response.put("temporaryToken", temporaryToken);
        response.put("redirectUrl", "/register");
        response.put("isNewAccount", true);
        response.put("name", newAccount.getName());
        response.put("email", newAccount.getEmail());
        response.put("userId", newAccount.getId());
    } else {
        Accounts account = optionalAccount.get();
        boolean hasKeywords = userKeywordRepository.existsByUserId(account.getId());
        if (!hasKeywords) {
            String temporaryToken = tokenService.generateTemporaryToken(providerId);
            response.put("temporaryToken", temporaryToken);
            response.put("redirectUrl", "/register");
        } else {
            String accessToken = tokenService.generateAccessToken(account);
            String refreshToken = tokenService.generateRefreshToken(account);
            response.put("accessToken", accessToken);
            response.put("refreshToken", refreshToken);
            response.put("redirectUrl", "/home");
        }
        response.put("userId", account.getId());
        response.put("name", account.getName());
        response.put("email", account.getEmail());
        response.put("profilePath", account.getProfilePath());
    }
    return response;
}


    // Access Token 받아오기
    private String getAccessToken(String authorizationCode) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String body = "grant_type=authorization_code" +
                "&client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&redirect_uri=" + redirectUri +
                "&code=" + authorizationCode;

        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                tokenUri,
                HttpMethod.POST,
                entity,
                new ParameterizedTypeReference<>() {
                }
        );

        Map<String, Object> responseBody = response.getBody();
        assert responseBody != null;
        return (String) responseBody.get("access_token");
    }

    // 사용자 정보 가져오기
    private Map<String, Object> getUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                userInfoUri,
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<>() {
                }
        );

        Map<String, Object> responseBody = response.getBody();
        log.info("카카오 사용자 정보: {}", responseBody);

        return response.getBody();
    }
}
