package newREALs.backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import newREALs.backend.DTO.*;
import newREALs.backend.domain.*;
import newREALs.backend.repository.*;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class ProfileService {
    private final UserRepository userRepository;
    private final UserKeywordRepository userKeywordRepository;
    private final AccountsRepository accountsRepository;

    public ProfileInfoDTO getProfileInfo(Long userId) {
        Accounts account = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("없는 userId"));

        // 유저 키워드 리스트에 저장하기
        List<Keyword> userKeywords = userKeywordRepository.findKeywordsById(userId);
        List<String> keywordList = new ArrayList<>();
        for(Keyword userKeyword : userKeywords){
            keywordList.add(userKeyword.getName());
        }

        return ProfileInfoDTO.builder()
                .user_id(account.getId())
                .name(account.getName())
                .email(account.getEmail())
                .profilePath(account.getProfilePath())
                .point(account.getPoint())
                .keywords(keywordList)
                .build();
    }

    public ProfileQuizStatusDTO getQuizStatus(Long userId) {
        Accounts account = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("없는 userId"));

        List<Quiz> quizList = accountsRepository.findQuizListByUserId(userId);
        List<QuizDTO> quizDTOList = new ArrayList<>();
        for (Quiz quiz : quizList) {
            quizDTOList.add(new QuizDTO(quiz));
        }

        List<Integer> quizStatus = accountsRepository.findQuizStatusByUserId(userId);

        return ProfileQuizStatusDTO.builder()
                .user_id(account.getId())
                .quizList(quizDTOList)
                .quizStatus(quizStatus)
                .build();
    }

    public ProfileAttendanceListDTO getAttendanceList(Long userId) {
        Accounts account = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("없는 userId"));

        List<Boolean> attendanceList = accountsRepository.findAttendanceListByUserId(userId);

        return ProfileAttendanceListDTO.builder()
                .user_id(account.getId())
                .attendanceList(attendanceList)
                .build();
    }


    public Pageable getPageInfo(int page) {
        List<Sort.Order> sorts = new ArrayList<>();
        sorts.add(Sort.Order.desc("uploadDate"));
        return PageRequest.of(page - 1, 9, Sort.by(sorts));
    }

    public Page<BaseNewsThumbnailDTO> getScrapNewsThumbnail(Long userId, int page) {
        Accounts account = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("없는 userId"));

        Pageable pageable = getPageInfo(page);

        // 스크랩 된 뉴스 가져와
        Page<Basenews> scrapNewsPage = accountsRepository.findScrapNewsByUserId(userId, pageable);

        return scrapNewsPage.map(basenews -> BaseNewsThumbnailDTO.builder()
                .basenewsId(basenews.getId())
                .category(basenews.getCategory().getName())
                .subCategory(basenews.getSubCategory().getName())
                .keyword(basenews.getKeyword().getName())
                .title(basenews.getTitle())
                .summary(basenews.getSummary())
                .imageUrl(basenews.getImageUrl())
                .date(basenews.getUploadDate().toString())
                .isScrap(true)
                .build()
        );
    }

    public Map<String, List<ProfileInterestDTO>> getInterest(Long userId) {
        Accounts account = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("없는 userId"));

        Map<String, List<ProfileInterestDTO>> result = new HashMap<>();

        Pageable three = PageRequest.of(0,3);

        result.put("total", new ArrayList<>());
        result.put("politics", new ArrayList<>());
        result.put("economy", new ArrayList<>());
        result.put("society", new ArrayList<>());

        // 카테고리 상관 없이 전체에서 3개 가져오기
        List<Object[]> totalInterest = accountsRepository.findTotalInterestByUserId(userId, three);
        List<ProfileInterestDTO> totalInterestDTO = getTotalPercentage(totalInterest);
        result.put("total", totalInterestDTO); // key를 total로

        // 카테고리 별로 3개 가져오기
        List<Object[]> categoryInterest = accountsRepository.findCategoryInterestByUserId(userId, three);
        Map<String, List<ProfileInterestDTO>> categoryInterestDTO = getCategoryPercentage(categoryInterest);
        result.putAll(categoryInterestDTO);


        return result;
    }

    private List<ProfileInterestDTO> getTotalPercentage(List<Object[]> interests) {
        List<ProfileInterestDTO> interestDTOList = new ArrayList<>();

        int total = 0;
        for (Object[] item : interests) {
            total += (int) item[2];
        }

        for (Object[] item : interests) {
            String category = (String) item[0];
            String subCategory = (String) item[1];
            int count = (int) item[2];

            int percentage = (int) Math.round((count * 100.0) / total);
            ProfileInterestDTO dto = ProfileInterestDTO.builder()
                    .category(category)
                    .subCategory(subCategory)
                    .percentage(percentage)
                    .build();
            interestDTOList.add(dto);
        }
        return interestDTOList;
    }

    private Map<String, List<ProfileInterestDTO>> getCategoryPercentage(List<Object[]> interests) {
        Map<String, List<ProfileInterestDTO>> result = new HashMap<>();
        Map<String, Integer> categoryTotals = new HashMap<>(); // 카테고리 별로 count 합 저장

        for (Object[] item : interests) {
            String category = (String) item[0];
            int count = (int) item[2];
            categoryTotals.put(category, categoryTotals.getOrDefault(category, 0) + count); // 기본값은 0으로
        }

        // 카테고리별 퍼센트 계산
        for (Object[] item : interests) {
            String category = (String) item[0];
            String subCategory = (String) item[1];
            int count = (int) item[2];
            int categoryTotal = categoryTotals.get(category);

            int percentage = 0;
            for (int j = 0; j < count; j++) {
                percentage = (int) Math.round((count * 100.0) / categoryTotal);
            }

            ProfileInterestDTO dto = ProfileInterestDTO.builder()
                    .category(category)
                    .subCategory(subCategory)
                    .percentage(percentage)
                    .build();

            if (!result.containsKey(category)) {
                result.put(category, new ArrayList<>());
            }
            result.get(category).add(dto);
        }
        return result;
    }
}
