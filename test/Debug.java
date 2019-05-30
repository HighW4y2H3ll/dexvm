
public class Debug extends Object {

    int var;

    public class Nested {
        int i;
        int j;
    }

    public Debug() {
        Nested n = new Nested();
        System.out.println("h");
        System.out.println("e");
        System.out.println("l");
        System.out.println("l");
        System.out.println("12345678");
        System.out.println("1234567812345678");
        System.out.println("o");
        int i = 22;
        int j = 11;
        int z = foo(1,2);
        double fz = 0.1234567;
        if (i == 0) {
            z = i + 1;
        } else {
            z = i + j;
        }
        var = z;
    }
    //public static void main(String[] args) {
    //}
    public static int foo(int i, int j) {
        int z = foo(1,2);
        double fz = 0.1234567;
        if (i == 0) {
            return i + 1;
        } else {
            z = i + j;
        }
        if (z == 3) {
            return z + 1;
        } else {
            return z - 1;
        }
    }
}
