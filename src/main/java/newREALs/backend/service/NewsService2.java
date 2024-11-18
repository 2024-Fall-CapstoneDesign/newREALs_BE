package newREALs.backend.service;

import lombok.RequiredArgsConstructor;
import newREALs.backend.domain.Basenews;
import newREALs.backend.domain.UserKeyword;
import newREALs.backend.dto.*;
import newREALs.backend.repository.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class NewsService2 {

    private final BaseNewsRepository baseNewsRepository;
    private final QuizRepository quizRepository;
    private final ScrapRepository scrapRepository;
    private final UserKeywordRepository userKeywordRepository;

    public ViewCategoryDTO getSubCategory(Long userid, String category, String subCategory, int page){
        Pageable pageable = getPageInfo(page);
        return getCategoryAndSubPage(baseNewsRepository.findAllBySubCategoryName(subCategory,pageable),category,userid);
    }

    //error처리해라//category처음 로딩시
    public ViewCategoryDTO getCategory(Long userid,String category,int page){
        Pageable pageable = getPageInfo(page);
        return getCategoryAndSubPage(baseNewsRepository.findAllByCategoryName(category,pageable),category,userid);
    }

    public SearchDTO getSearch(Long userid, String searchword, int page){
        Pageable pageable = getPageInfo(page);

        SearchDTO result;
        //검색어 필드 : 카테고리,소카테고리,키워드, 본문 타이틀,
        Page<Basenews> pageNews = baseNewsRepository.findAllByTitleContainingOrDescriptionContaining(searchword,pageable);
        List<BaseNewsThumbnailDTO> basenewsList = getBaseNewsList(pageNews,userid);
        result = new SearchDTO(basenewsList,pageNews.getTotalPages(),pageNews.getTotalElements());
        return result;
    }

    //common code 0
    public DailyNewsThumbnailDTO getDailyNewsOne(String category){
        DailyNewsThumbnailDTO dailynewsdto = null;

        //데일리 뉴스 5개 중 카테고리 맞춰서 1개 가져오기 .
        Optional<Basenews> dailynews = baseNewsRepository.findFirstByCategoryNameAndIsDailyNews(category,true);
        //퀴즈가져올 뉴스의 아이디 뽑기
        Long basenews_id = dailynews.get().getId();
        //퀴즈 question만 가져오기
        Optional<String> question = quizRepository.findQuizByBaseNewsId(basenews_id);
        question.orElse("없음");

        if(dailynews.isPresent() && question.isPresent()){
            dailynewsdto = new DailyNewsThumbnailDTO(

                    dailynews.get().getId(),
                    dailynews.get().getTitle(),
                    dailynews.get().getImageUrl(),
                    dailynews.get().getCategory().getName(),
                    dailynews.get().getSubCategory().getName(),
                    dailynews.get().getKeyword().getName(),
                    question.get()

            );

            System.out.println("dailyenews get 완료");
        }else {
            System.out.println("daily news & quiz가 없어요");
        }

        return dailynewsdto;
    }

    //getSubCategory, getCategory 페이지에 공통으로 쓰임.
    public ViewCategoryDTO getCategoryAndSubPage(Page<Basenews> repositoryFindBy,String category,Long userid){
        ViewCategoryDTO result;

        DailyNewsThumbnailDTO dailynewsdto =  getDailyNewsOne(category);

        Page<Basenews> page = repositoryFindBy;
        List<BaseNewsThumbnailDTO> basenewsList = getBaseNewsList(page,userid);

        result = new ViewCategoryDTO(dailynewsdto,basenewsList,page.getTotalPages(),page.getTotalElements());
        return result;
    }

    //common code 1 : page<basenews> -> list<dto>
    public List<BaseNewsThumbnailDTO> getBaseNewsList(Page<Basenews> page,Long userid){
        List<BaseNewsThumbnailDTO> basenewsdtolist = new ArrayList<>();

        if(page!=null){

            for(Basenews basenews : page){
                //scrap 여부 확인하기 매 리스트마다.
                boolean scrap = scrapRepository.existsByUser_IdAndBnews_Id(userid,basenews.getId());
                BaseNewsThumbnailDTO basenewsdto = new BaseNewsThumbnailDTO(
                        basenews.getId(),
                        basenews.getSubCategory().getName(),
                        basenews.getCategory().getName(),
                        basenews.getKeyword().getName(),
                        basenews.getTitle(),
                        basenews.getSummary(),
                        basenews.getImageUrl(),
                        basenews.getUploadDate(),
                        scrap

                );
                basenewsdtolist.add(basenewsdto);

            }
        }


        return basenewsdtolist;

    }

    //common code 2
    public Pageable getPageInfo(int page){
        List<Sort.Order> sorts = new ArrayList<>();
        sorts.add(Sort.Order.desc("uploadDate"));
        return  PageRequest.of(page-1,12,Sort.by(sorts));
    }


    public List<DailyNewsThumbnailDTO> getDailynewsList(){
        List<Basenews> dailynewsList = baseNewsRepository.findAllByIsDailyNews(true);
        List<DailyNewsThumbnailDTO> dailydtoList = new ArrayList<>();

        for(Basenews dnews : dailynewsList) {
            dailydtoList.add(
                    new DailyNewsThumbnailDTO(
                            dnews.getId(),
                            dnews.getTitle(),
                            dnews.getImageUrl(),
                            dnews.getCategory().getName(),
                            dnews.getSubCategory().getName(),
                            dnews.getKeyword().getName(),
                            "dd" //추후 수정
                    )
            );
        }

        return  dailydtoList;

    }


    //keywordIndex : 유저마다 최소 1개 최대 5개의 키워드를 리스트로 반환. 기본값은 keywordIndex =0으로 시작
    public KeywordNewsDTO getKeywordnewsList(Long userid, @RequestParam int keywordIndex, @RequestParam int page){

        //사용자의 키워드 list
        List<String> keywords = userKeywordRepository.findAllByUser_Id(userid);

        //키워드 뉴스 리스트
        String currentKeyword = keywords.get(keywordIndex);

        Pageable pageable = getPageInfo(page);
        Page<Basenews> pageNews = baseNewsRepository.findAllByKeywordName(currentKeyword,pageable);
        List<BaseNewsThumbnailDTO> keywordNewsList = getBaseNewsList(pageNews,userid);

        KeywordNewsDTO result = new KeywordNewsDTO(keywords,keywordNewsList,pageNews.getTotalPages(),pageNews.getTotalElements());

        return result;

    }



}