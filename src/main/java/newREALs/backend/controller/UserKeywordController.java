package newREALs.backend.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import newREALs.backend.domain.Accounts;
import newREALs.backend.domain.UserKeyword;
import newREALs.backend.dto.ApiResponseDTO;
import newREALs.backend.repository.UserRepository;
import newREALs.backend.service.TokenService;
import newREALs.backend.service.UserKeywordService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@Slf4j
@Transactional
@RestController
@RequiredArgsConstructor
@RequestMapping("/register")
public class UserKeywordController {

    private final UserKeywordService userKeywordService;
    private final TokenService tokenService;
    private final UserRepository userRepository;


    @PutMapping("/edit")
    public ResponseEntity<List<String>> editUserKeywords(HttpServletRequest userInfo, @RequestBody List<String> keywords){
        Long userid = tokenService.getUserId(userInfo);
        List<String> updateUserKeywods = userKeywordService.updateUserKeywords(keywords,userid);


        return ResponseEntity.status(HttpStatus.CREATED).body(updateUserKeywods);
    }

    //처음 키워드 만들기.
    @PostMapping
    public ResponseEntity<?> registerUserKeywords(HttpServletRequest request, @RequestBody List<String> keywords){
//        Long userid = tokenService.getUserId(userInfo);
        String temporaryToken = tokenService.extractTokenFromHeader(request);
        log.debug("임시토큰 : {}", temporaryToken);

        if (temporaryToken == null || !tokenService.validateTemporaryToken(temporaryToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponseDTO.failure("E401", "유효하지 않은 임시 토큰입니다."));
        }
        String providerId = tokenService.extractProviderIdFromTemporaryToken(temporaryToken);

        Accounts user = userRepository.findByProviderId(providerId)
                .orElseThrow(() -> new IllegalArgumentException("ProviderId에 해당하는 유저가 없습니다."));
        //실제 도메인 객체 생성
        List<UserKeyword> createdUserKeywords = userKeywordService.createUserKeywords(keywords,user.getId());
        //just 반환값
        List<String> result = new ArrayList<>();

        for(UserKeyword userKeyword : createdUserKeywords)
            result.add(userKeyword.getKeyword().getName());


        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("access_token", accessToken);
        responseBody.put("refresh_token", refreshToken);
        responseBody.put("keywords", result);

        return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
    }
}