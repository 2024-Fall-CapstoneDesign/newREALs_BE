package newREALs.backend.service;

import jakarta.transaction.Transactional;
import newREALs.backend.domain.*;
import newREALs.backend.dto.NewsDetailDto;
import newREALs.backend.dto.SimpleNewsDto;
import newREALs.backend.dto.TermDetailDto;
import newREALs.backend.repository.*;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class NewsDetailService {
    private final BasenewsRepository basenewsRepository;
    private final UserRepository userRepository;
    private final ScrapRepository scrapRepository;
    private final LikesRepository likesRepository;
    private final SubInterestRepository subInterestRepository;
    private final ClickRepository clickRepository;
    private final CategoryRepository categoryRepository;
    private final SubCategoryRepository subCategoryRepository;

    public NewsDetailService(BasenewsRepository basenewsRepository, UserRepository userRepository, ScrapRepository scrapRepository, LikesRepository likesRepository, SubInterestRepository subInterestRepository, ClickRepository clickRepository, CategoryRepository categoryRepository, SubCategoryRepository subCategoryRepository) {
        this.basenewsRepository = basenewsRepository;
        this.userRepository = userRepository;
        this.scrapRepository = scrapRepository;
        this.likesRepository = likesRepository;
        this.subInterestRepository = subInterestRepository;
        this.clickRepository = clickRepository;
        this.categoryRepository = categoryRepository;
        this.subCategoryRepository = subCategoryRepository;
    }


//    //뉴스 상세페이지 조회 메서드
//    @Transactional
//    public NewsDetailDto getNewsDetail(Long basenewsId, Long userId){
//        Basenews basenews=basenewsRepository.findById(basenewsId)
//                .orElseThrow(()->new IllegalArgumentException("Invalid news ID"));
//        Accounts user=userRepository.findById(userId)
//                .orElseThrow(()->new IllegalArgumentException("Invalid user ID"));
//
//        //조회수 증가
//        Optional<Click> click=clickRepository.findByUserAndBasenews(user,basenews);
//        if(!click.isPresent()){
//            //처음 클릭하는거면
//            Click c=new Click(user,basenews);
//            clickRepository.save(c);
//            basenews.setViewCount(basenews.getViewCount()+1);
//            basenewsRepository.save(basenews);
//        }else{
//            //내가 이걸 몇번 봤는지만 카운트.. 뉴스자체의 조회수는 안올라감
//            Click c= click.get();
//            c.setCount(c.getCount()+1);
//        }
//
//        //basenews를 newsdetailDTO로 변환
//        NewsDetailDto newsDetailDto=new NewsDetailDto(basenews);
//
//        //용어 목록도 DTO로 변환
//        List<TermDetailDto> termList=basenews.getTermList().stream()
//                .map(TermDetailDto::new)
//                .collect(Collectors.toList());
//        newsDetailDto.setTermList(termList);
//
//        //유저 스크랩여부 확인
//        Optional<Scrap> isScrapped=scrapRepository.findByUserAndBasenews(user,basenews);
//        boolean b=isScrapped.isPresent();
//        newsDetailDto.setScrapped(b);
//
//        return newsDetailDto;
//    }


    //스크랩 처리 메서드
    @Transactional
    public void getScrap(Long basenewsId, Long userId){
        Basenews basenews=basenewsRepository.findById(basenewsId)
                .orElseThrow(()->new IllegalArgumentException("Invalid news ID"));
        Accounts user=userRepository.findById(userId)
                .orElseThrow(()->new IllegalArgumentException("Invalid user ID"));
        //유저관심도
        Optional<SubInterest> subInterest= subInterestRepository.findByUserAndSubCategory(user,basenews.getSubCategory());
        //스크랩 여부 확인
        Optional<Scrap> isScrapped=scrapRepository.findByUserAndBasenews(user,basenews);

        //이미 스크랩 되어있던 거면 스크랩 해제
        if(isScrapped.isPresent()){
            scrapRepository.delete(isScrapped.get());
            //관심도를 삭제할지 말지?
            SubInterest s=subInterest.get();
            s.setCount(s.getCount()-2);
            subInterestRepository.save(s);
        } else{
            //스크랩 안되어있던 거면 스크랩 O
            Scrap newScrap=new Scrap(user,basenews);
            scrapRepository.save(newScrap);
            //관심도 증가
            if(subInterest.isPresent()){
                SubInterest s=subInterest.get();
                s.setCount(s.getCount()+3);
                subInterestRepository.save(s);
            }else{
                SubInterest s=new SubInterest(user,basenews.getSubCategory(),3);
                subInterestRepository.save(s);
            }
        }

    }

    //공감 버튼 처리
    //reactionType : 좋아요 0 슬퍼오 1 흥미로워요 2
    @Transactional
    public void getLikes(Long basenewsId, Long userId, int reactionType ){
        Basenews basenews=basenewsRepository.findById(basenewsId)
                .orElseThrow(()->new IllegalArgumentException("Invalid news ID"));
        Accounts user=userRepository.findById(userId)
                .orElseThrow(()->new IllegalArgumentException("Invalid user ID"));


        if (reactionType < 0 || reactionType >= 3) {
            throw new IllegalArgumentException("Invalid reaction type. It must be between 0 and 2.");
        }
        //Likes 객체 받아와서
        Optional<Likes> existingLike=likesRepository.findByUserAndBasenews(user,basenews);
        Optional<SubInterest> subInterest=subInterestRepository.findByUserAndSubCategory(user,basenews.getSubCategory());

        if(existingLike.isPresent()){
            //Likes 객체가 존재 : 이미 공감버튼 눌려 있다는 뜻
            Likes like=existingLike.get();
            if(like.getReactionType()==reactionType){ //화나요에 좋아요 눌러져있음 -> 또 화나요 클릭한 케이스
                basenews.getLikesCounts()[reactionType]--; //현재 반응 취소.
                //관심도 감소 할지말지??
                SubInterest s=subInterest.get();
                s.setCount(s.getCount()-1);
                subInterestRepository.save(s);
                likesRepository.delete(like);
            }else{ //화나요에 좋아요 눌러져있음 -> 좋아요 클릭한 케이스 : 아무일도 일어나지 않음

            }
        }else{
            //Likes 객체 없음 : 공감 버튼 안눌려있음
            basenews.getLikesCounts()[reactionType]++; //공감수 증가
            //관심도 증가.
            if(subInterest.isPresent()){
                SubInterest s=subInterest.get();
                if(reactionType<2){s.setCount(s.getCount()+1); } //좋아요, 슬퍼요는 +1
                else {s.setCount(s.getCount()+2);}  //흥미로워요는 +2
                subInterestRepository.save(s);
            }else{
                SubInterest s=new SubInterest(user,basenews.getSubCategory(),1);
                if(reactionType==2)s.setCount(s.getCount()+1); //흥미로워요는 +2여야하니까..
                subInterestRepository.save(s);

            }
            likesRepository.save(new Likes(basenews,user,reactionType));
        }


        //저장
        basenewsRepository.save(basenews);
    }

    //뉴스 상세페이지 조회 메서드
    @Transactional
    public NewsDetailDto getNewsDetail(Long basenewsId, Long userId, String cate, String subCate){
        Basenews basenews=basenewsRepository.findById(basenewsId)
                .orElseThrow(()->new IllegalArgumentException("Invalid news ID"));
        Accounts user=userRepository.findById(userId)
                .orElseThrow(()->new IllegalArgumentException("Invalid user ID"));


        //조회수 증가
        Optional<Click> click=clickRepository.findByUserAndBasenews(user,basenews);
        if(!click.isPresent()){
            //처음 클릭하는거면
            Click c=new Click(user,basenews);
            clickRepository.save(c);
            basenews.setViewCount(basenews.getViewCount()+1);
            basenewsRepository.save(basenews);
        }else{
            //내가 이걸 몇번 봤는지만 카운트.. 뉴스자체의 조회수는 안올라감
            Click c= click.get();
            c.setCount(c.getCount()+1);
        }

        //basenews를 newsdetailDTO로 변환
        NewsDetailDto newsDetailDto=new NewsDetailDto(basenews);

        //용어 목록도 DTO로 변환
        List<TermDetailDto> termList=basenews.getTermList().stream()
                .map(TermDetailDto::new)
                .collect(Collectors.toList());
        newsDetailDto.setTermList(termList);

        //유저 스크랩여부 확인
        Optional<Scrap> isScrapped=scrapRepository.findByUserAndBasenews(user,basenews);
        boolean b=isScrapped.isPresent();
        newsDetailDto.setScrapped(b);


        //이전, 다음 뉴스
        List<Basenews> sortedNews=fetchSortedNews(cate,subCate);
        Basenews prevNews=findPrevNews(sortedNews,basenewsId);
        Basenews nextNews=findNextNews(sortedNews,basenewsId);

        if(prevNews!=null){
            newsDetailDto.setPrevNews(new SimpleNewsDto(prevNews.getId(),prevNews.getTitle()));
        }
        if (nextNews != null) {
            newsDetailDto.setNextNews(new SimpleNewsDto(nextNews.getId(), nextNews.getTitle()));
        }
        return newsDetailDto;
    }

//    //같은 카테고리/서브카테고리에 속하는 basenews 리스트 만듦
//    private List<Basenews> fetchSortedNews(String cate, String subCate){
//        Optional<Category> category=categoryRepository.findByName(cate);
//        Optional<SubCategory> subCategory=subCategoryRepository.findByName(subCate);
//
//        if(subCategory.isPresent()){
//            return basenewsRepository.findByCategoryAndSubCategoryOrderByIdAsc(category.get(), subCategory.get());
//        }
//        //sub가 없으면 카테고리 기준으로 필터링
//        return basenewsRepository.findByCategoryOrderByIdAsc(category.get());
//    }

    // 같은 카테고리/서브카테고리에 속하는 Basenews 리스트 생성
    private List<Basenews> fetchSortedNews(String cate, String subCate) {
        Category category = categoryRepository.findByName(cate)
                .orElseThrow(() -> new IllegalArgumentException("Invalid category name: " + cate));

        if (subCate != null && !subCate.isEmpty()) {
            SubCategory subCategory = subCategoryRepository.findByName(subCate)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid subcategory name: " + subCate));
            return basenewsRepository.findByCategoryAndSubCategoryOrderByIdAsc(category, subCategory);
        }

        // 서브카테고리가 없는 경우 카테고리 기준
        return basenewsRepository.findByCategoryOrderByIdAsc(category);
    }

    private Basenews findPrevNews(List<Basenews> sortedNews, Long curId) {
        for (int i = 0; i < sortedNews.size(); i++) {
            if (sortedNews.get(i).getId().equals(curId) && i > 0) {
                return sortedNews.get(i - 1); // 현재 뉴스 이전의 뉴스 반환
            }
        }
        return null; // 이전 뉴스가 없을 경우
    }
    private Basenews findNextNews(List<Basenews> sortedNews, Long curId) {
        for (int i = 0; i < sortedNews.size(); i++) {
            if (sortedNews.get(i).getId().equals(curId) && i < sortedNews.size() - 1) {
                return sortedNews.get(i + 1); // 현재 뉴스 다음의 뉴스 반환
            }
        }
        return null; // 다음 뉴스가 없을 경우
    }



}
