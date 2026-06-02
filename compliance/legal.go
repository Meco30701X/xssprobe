package compliance

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ConfirmLegalUsage displays a legal disclaimer and asks for user confirmation
// Returns true if user confirms, false otherwise
// If skipConfirm is true, returns true without prompting (for CI/CD automation)
func ConfirmLegalUsage(skipConfirm bool) bool {
	if skipConfirm {
		return true
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("⚠️  法律声明 / Legal Disclaimer")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("此工具仅用于授权安全测试。未经授权对系统进行测试")
	fmt.Println("可能违反《中华人民共和国网络安全法》等法律法规。")
	fmt.Println()
	fmt.Println("This tool is for authorized security testing only.")
	fmt.Println("Unauthorized testing may violate applicable laws.")
	fmt.Println()
	fmt.Println("请确认 / Please confirm:")
	fmt.Println("  1. 您拥有目标系统的书面测试授权")
	fmt.Println("     You have written authorization for the target system")
	fmt.Println()
	fmt.Println("  2. 您了解测试可能对目标系统产生的影响")
	fmt.Println("     You understand the potential impact on the target system")
	fmt.Println()
	fmt.Println("  3. 您将承担测试的全部法律责任")
	fmt.Println("     You accept full legal responsibility for the testing")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\n确认继续 / Confirm to proceed? [y/N]: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		switch input {
		case "y", "yes":
			fmt.Println("✓ 已确认 / Confirmed. Proceeding with authorized testing.")
			return true
		case "n", "no", "":
			fmt.Println("✗ 已取消 / Cancelled. Exiting.")
			return false
		default:
			fmt.Println("请输入 y 或 n / Please enter y or n")
		}
	}
}
