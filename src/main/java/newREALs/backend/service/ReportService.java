package newREALs.backend.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import newREALs.backend.domain.Accounts;
import newREALs.backend.domain.UserKeyword;
import newREALs.backend.dto.ReportCompareDto;
import newREALs.backend.dto.ReportInterestDto;
import newREALs.backend.repository.*;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ReportService {
    private final UserRepository userRepository;
    private final UserKeywordRepository userKeywordRepository;
    private final KeywordRepository keywordRepository;
    private final ChatGPTService chatGPTService;
    private final SubInterestRepository subInterestRepository;
    private final PreSubInterestRepository preSubInterestRepository;
    private final InsightService insightService;

    public Map<String, Object> generateReportData(Long userId) {
        // 서현
        Map<String, List<ReportInterestDto>> interest = getReportInterest(userId);
        Map<String, Object> change = getChangeGPT(userId);
        Map<String, List<ReportCompareDto>> compare = getReportCompareLast(userId);
        // 현진 - GPT 추가해야됨
        List<String> keyword = recommendNewKeyword(userId);

        Map<String, Object> data = new HashMap<>();
        data.put("interest", interest);
        data.put("change", change);
        data.put("compare", compare);
        data.put("keyword", keyword);

        return data;
    }


    public String getAnalysisSummary(Long userId){
        String summary=null;
        return summary;
    }
    public List<String> recommendNewKeyword(Long userId){
        Accounts user=userRepository.findById(userId)
                .orElseThrow(()->new EntityNotFoundException("해당 ID의 사용자를 찾을 수 없습니다."));
        //관심키워드 가져옴. 인덱스=id Long 변환
        Map<Long, Integer> keywordMap = new HashMap<>();
        for (int i = 0; i < user.getKeywordInterest().size(); i++) {
            keywordMap.put((long)(i + 1), user.getKeywordInterest().get(i)); // ID는 1부터 시작
        }
        //이미 등록된 키워드 가져옴
        List<UserKeyword> userKeywords=userKeywordRepository.findAllByUserId(userId);
        Set<Long> excludeKeywordIds=userKeywords.stream()
                .map(UserKeyword::getKeywordId)
                .collect(Collectors.toSet());
        //이미 등록된 키워드 제외하고 상위 5개 찾기
        List<Long> keywordIDs= keywordMap.entrySet().stream()
                .filter(entry->!excludeKeywordIds.contains(entry.getKey()))
                .sorted((e1,e2)->e2.getValue().compareTo(e1.getValue()))
                .limit(5)
                .map(Map.Entry::getKey)
                .toList();

        //ID->이름 변환
        return keywordIDs.stream()
                .map(keywordRepository::findNameById)
                .collect(Collectors.toList());

    }


    @Transactional
    public void processReport(Long userId) throws Throwable{
        //시작시간
        long startTime = System.nanoTime();
        System.out.println("processReport in ");
        Accounts user=userRepository.findById(userId)
                .orElseThrow(()->new EntityNotFoundException("해당 ID의 사용자를 찾을 수 없습니다."));

        //1. 서현언니 분석 + 2.
        List<Map<String,String>> Messages=new ArrayList<>();
        Messages.add(Map.of("role","system","content",
                "..."));

        Messages.add(Map.of("role", "user", "content",
                "해야할 일이 크게 2가지이다. "
        ));

        String result=(String) chatGPTService.generateContent(Messages).get("text");
        System.out.println("gpt result");
        System.out.println(result);

        //처이 완료 시간
        long endTime = System.nanoTime();
        long duration = (endTime - startTime) / 1_000_000; // 밀리초로 변환

        System.out.println("Execution time for processArticle: " + duration + " ms");
    }

    // 레포트 - 관심도 분석 부분
    public Map<String, List<ReportInterestDto>> getReportInterest(Long userId) {
        Map<String, List<ReportInterestDto>> result = new HashMap<>();

        result.put("society", new ArrayList<>());
        result.put("politics", new ArrayList<>());
        result.put("economy", new ArrayList<>());

        int societyCount = subInterestRepository.findCountByUserIdAndCategory(userId, "society");
        int politicsCount = subInterestRepository.findCountByUserIdAndCategory(userId, "politics");
        int economyCount = subInterestRepository.findCountByUserIdAndCategory(userId, "economy");

        List<Integer> categoryCount = new ArrayList<>();
        categoryCount.add(societyCount);
        categoryCount.add(politicsCount);
        categoryCount.add(economyCount);

        int totalCount = societyCount + politicsCount + economyCount;

        int societyQuiz = subInterestRepository.findQuizCountByUserIdAndCategory(userId, "society");
        int societyComment = subInterestRepository.findCommentCountByUserIdAndCategory(userId, "society");
        int societyScrap = subInterestRepository.findScrapCountByUserIdAndCategory(userId, "society");

        int politicsQuiz = subInterestRepository.findQuizCountByUserIdAndCategory(userId, "politics");
        int politicsComment = subInterestRepository.findCommentCountByUserIdAndCategory(userId, "politics");
        int politicsScrap = subInterestRepository.findScrapCountByUserIdAndCategory(userId, "politics");

        int economyQuiz = subInterestRepository.findQuizCountByUserIdAndCategory(userId, "economy");
        int economyComment = subInterestRepository.findCommentCountByUserIdAndCategory(userId, "economy");
        int economyScrap = subInterestRepository.findScrapCountByUserIdAndCategory(userId, "economy");

        List<Integer> percentage = getReportPercentage(categoryCount, totalCount);

        result.get("society").add(ReportInterestDto.builder()
                .percentage(percentage.get(0))
                .quiz(societyQuiz)
                .insight(societyComment)
                .scrap(societyScrap)
                .build());

        result.get("politics").add(ReportInterestDto.builder()
                .percentage(percentage.get(1))
                .quiz(politicsQuiz)
                .insight(politicsComment)
                .scrap(politicsScrap)
                .build());

        result.get("economy").add(ReportInterestDto.builder()
                .percentage(percentage.get(2))
                .quiz(economyQuiz)
                .insight(economyComment)
                .scrap(economyScrap)
                .build());

        return result;
    }

    private List<Integer> getReportPercentage(List<Integer> catCount, int totCount) {
        List<Integer> percentages = new ArrayList<>();
        if (totCount == 0) {
            return List.of(0, 0, 0);
        }

        int percentageSum = 0;
        int maxIndex = -1;
        int maxValue = 0;

        for (int i = 0; i < catCount.size(); i++) {
            int count = catCount.get(i);
            int percentage = (int) Math.round((count * 100.0) / totCount);
            percentages.add(percentage);
            percentageSum += percentage;

            if (count > maxValue) {
                maxValue = count;
                maxIndex = i;
            }
        }

        // 퍼센트 합 100 안되면 제일 큰 항목에 그 차이만큼 더해주기
        int difference = 100 - percentageSum;
        if (difference != 0 && maxIndex != -1) {
            percentages.set(maxIndex, percentages.get(maxIndex) + difference);
        }

        return percentages;
    }

    // 관심 변화 트렌드
    // 지난 달 데이터 0이면 null로
    public Map<String, Object> getReportChange(Long userId) {
        Map<String, Object> result = new HashMap<>();
        result.put("GPTComment", "GPT 응답 넣을게요");

        Integer lastSociety = preSubInterestRepository.findCountByUserIdAndCategory(userId, "society");
        Integer lastPolitics = preSubInterestRepository.findCountByUserIdAndCategory(userId, "politics");
        Integer lastEconomy = preSubInterestRepository.findCountByUserIdAndCategory(userId, "economy");

        boolean hasLastSocietyData = lastSociety != null && lastSociety > 0;
        boolean hasLastPoliticsData = lastPolitics != null && lastPolitics > 0;
        boolean hasLastEconomyData = lastEconomy != null && lastEconomy > 0;

        boolean hasNoLastData = !hasLastSocietyData && !hasLastPoliticsData && !hasLastEconomyData;
        result.put("hasNoLastData", hasNoLastData);

        Integer thisSociety = subInterestRepository.findCountByUserIdAndCategory(userId, "society");
        Integer thisPolitics = subInterestRepository.findCountByUserIdAndCategory(userId, "politics");
        Integer thisEconomy = subInterestRepository.findCountByUserIdAndCategory(userId, "economy");

        Map<String, Integer> changeMap = new HashMap<>();
        if (hasLastSocietyData) {
            changeMap.put("society", getChangeInt(lastSociety, thisSociety));
        }
        else {
            changeMap.put("society", null);
        }

        if (hasLastPoliticsData) {
            changeMap.put("politics", getChangeInt(lastPolitics, thisPolitics));
        }
        else {
            changeMap.put("politics", null);
        }

        if (hasLastEconomyData) {
            changeMap.put("economy", getChangeInt(lastEconomy, thisEconomy));
        }
        else {
            changeMap.put("economy", null);
        }

        String biggest = null;
        Integer maxChange = null;

        for (Map.Entry<String, Integer> entry : changeMap.entrySet()) {
            Integer value = entry.getValue();
            if (value != null && (maxChange == null || value > maxChange)) {
                maxChange = value;
                biggest = entry.getKey();
            }
        }
        if (biggest != null) {
            result.put("biggest", biggest);
        }

        result.putAll(changeMap);
        return result;
    }

    // 증가율 계산
    private int getChangeInt(int lastMonth, int thisMonth) {
        if (thisMonth == 0) {
            if (lastMonth == 0) {
                return 0;
            } else {
                return -100;
            }
        }

        if (lastMonth == 0) {
            return 100;
        }
        int difference = thisMonth - lastMonth;
        double percentageChange = ((double) difference / lastMonth) * 100;
        return (int) Math.round(percentageChange);
    }

    // 지난 달이랑 활동 비교
    public Map<String, List<ReportCompareDto>> getReportCompareLast(Long userId) {
        Map<String, List<ReportCompareDto>> result = new HashMap<>();
        result.put("lastMonth", new ArrayList<>());
        result.put("thisMonth", new ArrayList<>());

        int lastQuiz = preSubInterestRepository.findTotalQuizCountByUserId(userId);
        int lastComment = preSubInterestRepository.findTotalCommentCountByUserId(userId);
        int lastAtt = preSubInterestRepository.findTotalAttCountByUserId(userId);

        int thisQuiz = subInterestRepository.findTotalQuizCountByUserId(userId);
        int thisComment = subInterestRepository.findTotalCommentCountByUserId(userId);
        int thisAtt = subInterestRepository.findTotalAttCountByUserId(userId);

        result.get("lastMonth").add(ReportCompareDto.builder()
                .quiz(lastQuiz)
                .insight(lastComment)
                .attendance(lastAtt)
                .build());
        result.get("thisMonth").add(ReportCompareDto.builder()
                .quiz(thisQuiz)
                .insight(thisComment)
                .attendance(thisAtt)
                .build());
        return result;
    }

    public Map<String, Object> getChangeGPT(Long userId) {
        long startTime = System.nanoTime();
        System.out.println("분석 레포트 Change GPT 호출 시작");

        Map<String, Object> changeData = getReportChange(userId);
        String stringChangeData = changeData.toString();

        List<Map<String, String>> message = new ArrayList<>();
        message.add(Map.of("role", "system", "content",
                "유저의 지난 달과 이번 달의 활동을 비교한 결과를 보고 유저가 이해하기 쉽게 3문장 정도로 분석해줘."));
        message.add(Map.of("role", "system", "content",
                "다음은 유저의 지난 달, 이번 달의 활동을 비교한 데이터야: \n"
                        + stringChangeData
                        + "데이터는 다음과 같은 필드로 구성되어 있어: \n"
                        + "**politics**, **society**, **economy** : 해당 카테고리에서의 뉴스 활동 변화율.\n 값이 양수면 그만큼 활동 증가, 음수면 그만큼 활동 감소, null이면 해당 카테고리는 지난 달 활동이 없는 거야.\n"
                        + "**biggest** : 유저의 활동량 변화량이 큰 카테고리야.\n"
                        + "**hasNoLastData** : 지난 달에 세 카테고리 모두 지난 달 활동이 없었는지를 보여주는 boolean형 데이터야.\n"
                        + "너가 해야하는 건 다음과 같아.\n"
                        + "1. 만약 모든 카테고리가 null이라면 지난 달에 활동이 없었던거라 의미있는 분석이 어렵다는 걸 언급해줘.\n"
                        + "2. 분석에는 가장 변화가 컸던 카테고리, 지난 달 데이터가 없었다면 그거에 대한 언급도 되어있으면 좋겠어.\n"
                        + "3. 결과를 바탕으로 유저에게 활동 변화에 대한 간략한 분석을 해줘.\n"
                        + "4. '~했어요'와 같은 말투로 분석 결과를 3줄로 알려줘.\n"
                        + "5. 분석 예시: 이번 11월, 뉴스님은 사회 분야에 가장 큰 관심을 보였어요. 특히, 전세사기와 같은 주거 안정 문제와 강력 범죄 관련 이슈에 대해 높은 참여을 보였어요. 경제 분야에서도 일부 관심이 있었지만, 생활과 직접적으로 연관된 사회적 문제에 대한 관심이 가장 두드러졌어요."));

        String result = (String) chatGPTService.generateContent(message).get("text");
        changeData.put("GPTComment", result);

        long endTime = System.nanoTime();
        long duration = (endTime - startTime) / 1_000_000;
        System.out.println("GPT 실행 시간: " + duration + "ms");

        return changeData;
    }
}
