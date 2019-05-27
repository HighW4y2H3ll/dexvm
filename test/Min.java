
public class Min {
    public Min() {
        System.out.println("h");
        System.out.println("e");
        System.out.println("l");
        System.out.println("l");
        System.out.println("o");
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
