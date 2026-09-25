import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;

/** Runs each supplied .fga fixture through the pinned generated grammar. */
public final class ConformanceRunner {
    private ConformanceRunner() {}

    private static final class CountingErrorListener extends BaseErrorListener {
        private int count;

        @Override
        public void syntaxError(
                Recognizer<?, ?> recognizer,
                Object offendingSymbol,
                int line,
                int charPositionInLine,
                String message,
                RecognitionException exception) {
            count++;
        }
    }

    public static void main(String[] arguments) throws IOException {
        if (arguments.length == 0) {
            throw new IllegalArgumentException("usage: ConformanceRunner <fixture-file-or-directory>...");
        }

        List<Path> fixtures = new ArrayList<>();
        for (String argument : arguments) {
            Path path = Path.of(argument);
            if (Files.isDirectory(path)) {
                try (Stream<Path> paths = Files.walk(path)) {
                    paths.filter(Files::isRegularFile)
                            .filter(candidate -> candidate.toString().endsWith(".fga"))
                            .forEach(fixtures::add);
                }
            } else if (path.toString().endsWith(".fga")) {
                fixtures.add(path);
            }
        }
        fixtures.sort(Comparator.comparing(path -> path.toString()));

        for (Path fixture : fixtures) {
            String input = Files.readString(fixture, StandardCharsets.UTF_8);
            CountingErrorListener lexerErrors = new CountingErrorListener();
            CountingErrorListener parserErrors = new CountingErrorListener();

            OpenFGALexer lexer = new OpenFGALexer(CharStreams.fromString(input));
            lexer.removeErrorListeners();
            lexer.addErrorListener(lexerErrors);

            OpenFGAParser parser = new OpenFGAParser(new CommonTokenStream(lexer));
            parser.removeErrorListeners();
            parser.addErrorListener(parserErrors);
            parser.main();

            int diagnosticCount = lexerErrors.count + parserErrors.count;
            String id = fixture.getFileName().toString().replaceFirst("\\.fga$", "");
            System.out.printf(
                    "{\"fixture_id\":\"%s\",\"accepted\":%s,\"diagnostic_count\":%d}%n",
                    jsonEscape(id),
                    diagnosticCount == 0,
                    diagnosticCount);
        }
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
