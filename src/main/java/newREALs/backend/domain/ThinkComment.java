package newREALs.backend.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

@Entity
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ThinkComment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(updatable = false)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "news_id", nullable = false)
    @OnDelete(action= OnDeleteAction.CASCADE)
    private Basenews basenews;

    @Column
    private String topic;

    @Column
    private String AIComment;

    @Column
    private String pros;
    @Column
    private String cons;
    @Column
    private String neutral;

    //배열로 관리 ?

    @Builder
    public ThinkComment(String topic,String AIComment,Basenews basenews){
        this.topic = topic;
        this.AIComment = AIComment;
        this.basenews= basenews;
    }



}
