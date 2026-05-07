<?php

// SECURITY: Load configuration and secure session management
// LOGIC: Initialize page context and title
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/templates/session.php';
$pageTitle = 'Home - AMC Marketplace';

// SECURITY: Authorization Check (Determine if current user has admin privileges)
$isAdmin = isset($_SESSION['role']) && $_SESSION['role'] === 'admin';

// --- ACTION HANDLERS ---

// LOGIC: Handle "Add to Cart" form submission
// 1. Handle ADD TO CART
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_to_cart'])) {
    // SECURITY: Validate CSRF token to prevent cross-site request forgery
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        die('Invalid request. Please refresh the page and try again.');
    }

    // SECURITY: Enforce authentication (User must be logged in to shop)
    if (!isset($_SESSION['user_id'])) {
        header('Location: ' . BASE_URL . '/pages/login.php');
        exit;
    }

    // INPUT: Cast inputs to integers to prevent injection
    $user_id = (int) $_SESSION['user_id'];
    $item_id = (int) $_POST['item_id'];
    $quantity = 1;

    // DATABASE: Validate item existence and active status
    // SECURITY: Use prepared statements
    $validateStmt = $conn->prepare("SELECT stock_quantity FROM items WHERE item_id = ? AND is_active = 1");
    $validateStmt->bind_param("i", $item_id);
    $validateStmt->execute();
    $validateResult = $validateStmt->get_result();

    // LOGIC: Stop if item invalid or out of stock
    if ($validateResult->num_rows === 0) {
        $validateStmt->close();
        die('Invalid item.');
    }

    $itemData = $validateResult->fetch_assoc();
    if ($itemData['stock_quantity'] < 1) {
        $validateStmt->close();
        die('Item is out of stock.');
    }
    $validateStmt->close();

    // DATABASE: Check if item is already in user's cart
    $checkStmt = $conn->prepare("SELECT quantity FROM cart WHERE user_id = ? AND item_id = ?");
    $checkStmt->bind_param("ii", $user_id, $item_id);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();

    if ($checkResult->num_rows > 0) {
        // LOGIC: Item exists, so update quantity
        $updateStmt = $conn->prepare("UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND item_id = ?");
        $updateStmt->bind_param("iii", $quantity, $user_id, $item_id);
        $updateStmt->execute();
        $updateStmt->close();
    } else {
        // LOGIC: Item is new to cart, so insert new row
        $insertStmt = $conn->prepare("INSERT INTO cart (user_id, item_id, quantity) VALUES (?, ?, ?)");
        $insertStmt->bind_param("iii", $user_id, $item_id, $quantity);
        $insertStmt->execute();
        $insertStmt->close();
    }
    $checkStmt->close();

    // FLOW: Redirect back to home with success flag
    header('Location: index.php?added=1');
    exit();
}

// LOGIC: Handle "Delete Item" request (Soft delete)

// 2. Handle DELETE (Admin)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete'])) {
    // SECURITY: Authentication check, user must be logged in to perform any actions
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        die('Unauthorized');
    }

    // SECURITY: Authorization check, only admins can delete items
    if (!$isAdmin) {
        http_response_code(403);
        die('Forbidden');
    }

    // SECURITY: CSRF token validation, prevent forged requests
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(400);
        die('Invalid request.');
    }

    // INPUT VALIDATION: ensure the posted item id is a real integer
    // FILTER_VALIDATE_INT rejects non-numeric strings (e.g., "abc")
    $item_id = filter_input(INPUT_POST, 'delete', FILTER_VALIDATE_INT);

    if ($item_id === false || $item_id === null) {
        http_response_code(400);
        die('Invalid item.');
    }

    // DATABASE: Perform soft delete (set is_active = 0)
    // SECURITY: prepared statement prevents SQL Injection
    $stmt = $conn->prepare('UPDATE items SET is_active = 0 WHERE item_id = ?');
    $stmt->bind_param('i', $item_id);

    $stmt->execute();

    // If 0 rows are affected, the item either doesn't exist or is already inactive
    if ($stmt->affected_rows === 0) {
        $stmt->close();
        http_response_code(404);
        die('Item not found or already deleted.');
    }

    // Close statement and redirect on success (prevents resubmission on refresh)
    $stmt->close();
    header('Location: index.php?deleted=1');
    exit();
}

// --- SEARCH FUNCTION ---

// INPUT: sanitize search term
$searchTerm = isset($_GET['search']) ? trim($_GET['search']) : '';
// SECURITY: Limit input length to prevent DOS/Buffer overflow attempts
$searchTerm = mb_substr($searchTerm, 0, 60);

// SECURITY: Remove null bytes to prevent poisoning attacks
if ($searchTerm !== '' && preg_match('/[\x00-\x1F\x7F]/', $searchTerm)) {
    $searchTerm = '';
}

if ($searchTerm !== '') {
    // LOGIC: Split search string into individual words for broader matching
    $words = preg_split('/\s+/', $searchTerm, -1, PREG_SPLIT_NO_EMPTY);
    // SECURITY: Cap number of keywords to prevent query complexity abuse
    $words = array_slice($words, 0, 5);

    // DATABASE: Build dynamic prepared statement components
    $whereParts = [];
    $params = [];
    $types = '';

    foreach ($words as $w) {
        // SECURITY: Escape LIKE wildcards to prevent logic manipulation
        $w = str_replace(['\\', '%', '_'], ['\\\\', '\%', '\_'], $w);
        $whereParts[] = "name LIKE ? ESCAPE '\\\\'";
        $params[] = '%' . $w . '%';
        $types .= 's';
    }

    // SQL: search only active items, order newest first, limit results to avoid heavy loads
    // SECURITY: parameters are bound separately to prevent SQL Injection
    $sql = "SELECT * FROM items
            WHERE is_active = 1
              AND (" . implode(' OR ', $whereParts) . ")
            ORDER BY created_at DESC
            LIMIT 50";

    // SECURITY: Execute dynamic prepared statement
    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();

    // Fetch results to display in the product grid
    $result = $stmt->get_result();
    $stmt->close();
} else {
    // LOGIC: If no search term is provided, show all active items
    $sql = "SELECT * FROM items WHERE is_active = 1 ORDER BY created_at DESC";
    $result = $conn->query($sql);
}

// SECURITY: Generate CSRF token for forms on this page
$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8'); ?></title>
    <link rel="stylesheet" href="<?php echo htmlspecialchars(BASE_URL, ENT_QUOTES, 'UTF-8'); ?>/css/style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link
        href="https://fonts.googleapis.com/css2?family=Cal+Sans:wght@400;500;600&family=Roboto:wght@300;400;500;700&display=swap"
        rel="stylesheet">
</head>

<body>
    <?php include __DIR__ . '/templates/header.php'; ?>

    <main class="container">
        <div class="card">

            <div class="about-section">
                <h2>The premier hub for <span class="highlight-blue">engineering</span> components.</h2>
                <p>
                    AMC Marketplace lets you discover and buy essential engineering components.
                    From the classic Raspberry Pi to the Ultrasonic Sensor, we connect you with
                    the tools needed to bring your ideas to life.
                </p>
            </div>

            <div class="header-row">
                <h1>Explore our products.</h1>
            </div>

            <?php if ($isAdmin): ?>
                <div class="admin-status-row">
                    <p class="admin-info-text">
                        You are logged in as <strong>Admin</strong>. Normal View shows all orders (read-only).
                    </p>
                    <div class="toggle-wrapper">
                        <span class="toggle-label">Normal</span>
                        <label class="switch">
                            <input type="checkbox" id="adminToggle" checked>
                            <span class="slider round"></span>
                        </label>
                        <span class="toggle-label">Admin View</span>
                    </div>
                </div>
            <?php endif; ?>

            <?php if (isset($_GET['deleted'])): ?>
                <div class="alert alert-success">Product deleted successfully.</div>
            <?php endif; ?>

            <?php if (isset($_GET['added'])): ?>
                <div class="alert alert-success">Item added to cart successfully!</div>
            <?php endif; ?>

            <?php if (isset($_GET['error'])): ?>
                <div class="alert alert-error">An error occurred. Please try again.</div>
            <?php endif; ?>

            <div class="search-container">
                <form method="GET" action="index.php" class="search-form">
                    <input type="text" name="search" placeholder="Search components..."
                        value="<?php echo htmlspecialchars($searchTerm, ENT_QUOTES, 'UTF-8'); ?>" class="search-input">

                    <button type="submit" class="btn search-btn">Search</button>

                    <?php if ($searchTerm !== ''): ?>
                        <a href="index.php" class="btn search-clear">Clear</a>
                    <?php endif; ?>
                </form>
            </div>

            <?php
            // LOGIC: Determine if grid should be shown (Admin sees even if empty, usually)
            $showGrid = $isAdmin || ($result && $result->num_rows > 0);
            ?>

            <?php if ($showGrid): ?>
                <div class="products-grid">

                    <?php if ($isAdmin): ?>
                        <a href="<?php echo htmlspecialchars(BASE_URL, ENT_QUOTES, 'UTF-8'); ?>/pages/add_item.php"
                            class="product-card add-card admin-element">
                            <div class="add-card-inner">
                                <div class="add-plus">+</div>
                                <div class="add-text">Add Item</div>
                            </div>
                        </a>
                    <?php endif; ?>

                    <?php
                    // LOGIC: Iterate through database results to display products
                    if ($result && $result->num_rows > 0):
                        $result->data_seek(0);
                        while ($row = $result->fetch_assoc()):
                            ?>
                            <div class="product-card">
                                <h3><?php echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'); ?></h3>
                                <img src="<?php echo htmlspecialchars(BASE_URL . UPLOAD_PATH . $row['image_url'], ENT_QUOTES, 'UTF-8'); ?>"
                                    alt="<?php echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'); ?>" class="product-image">
                                <p class="description"><?php echo htmlspecialchars($row['description'], ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="price">
                                    $<?php echo htmlspecialchars(number_format($row['price'], 2), ENT_QUOTES, 'UTF-8'); ?></p>
                                <p class="stock">Stock: <?php echo (int) $row['stock_quantity']; ?></p>

                                <?php if ((int) $row['stock_quantity'] > 0): ?>
                                    <form method="POST" action="index.php">
                                        <input type="hidden" name="csrf_token"
                                            value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="item_id" value="<?php echo (int) $row['item_id']; ?>">
                                        <button type="submit" name="add_to_cart" class="btn btn-cart">Add To Cart</button>
                                    </form>
                                <?php else: ?>
                                    <button readonly class="btn out-of-stock"
                                        style="background-color: #f0f0f0; cursor: not-allowed;">Out Of Stock</button>
                                <?php endif; ?>

                                <button type="button" class="btn btn-learn-more" data-id="<?php echo (int) $row['item_id']; ?>"
                                    data-name="<?php echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'); ?>"
                                    data-image="<?php echo htmlspecialchars(BASE_URL . UPLOAD_PATH . $row['image_url'], ENT_QUOTES, 'UTF-8'); ?>"
                                    data-desc="<?php echo htmlspecialchars($row['description'], ENT_QUOTES, 'UTF-8'); ?>"
                                    data-price="<?php echo htmlspecialchars(number_format($row['price'], 2), ENT_QUOTES, 'UTF-8'); ?>"
                                    data-stock="<?php echo (int) $row['stock_quantity']; ?>"
                                    data-specs="<?php echo htmlspecialchars($row['specifications'] ?? 'No specifications available.', ENT_QUOTES, 'UTF-8'); ?>">
                                    Learn More
                                </button>

                                <?php if ($isAdmin): ?>
                                    <div class="admin-actions admin-element">
                                        <a href="<?php echo htmlspecialchars(BASE_URL, ENT_QUOTES, 'UTF-8'); ?>/pages/edit_item.php?item_id=<?php echo (int) $row['item_id']; ?>"
                                            class="btn btn-edit">Edit</a>
                                        <form method="post"
                                            action="<?php echo htmlspecialchars(BASE_URL, ENT_QUOTES, 'UTF-8'); ?>/index.php"
                                            onsubmit="return confirm('Deactivate this item?')">
                                            <input type="hidden" name="csrf_token"
                                                value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                                            <input type="hidden" name="delete" value="<?php echo (int) $row['item_id']; ?>">
                                            <button type="submit" class="btn btn-danger">Delete</button>
                                        </form>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <?php
                        endwhile;
                    endif;
                    ?>
                </div>
            <?php else: ?>
                <p style="text-align:center; margin-top:20px; color:#666;">No products found.</p>
            <?php endif; ?>
        </div>
    </main>

    <div id="learnMoreModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Product Name</h2>
                <span class="close-btn">&times;</span>
            </div>
            <div class="modal-body">
                <img id="modalImage" src="" alt="" class="modal-image">

                <div class="modal-price" id="modalPrice"></div>
                <div class="modal-stock" id="modalStock"></div>

                <span class="modal-label">Description:</span>
                <p id="modalDesc"></p>

                <hr style="border:0; border-top:1px solid #eee; margin:20px 0;">

                <span class="modal-label">Specifications:</span>
                <p id="modalSpecs" style="white-space: pre-line;"></p>
            </div>

            <div class="modal-footer">
                <form id="modalForm" method="POST" action="index.php">
                    <input type="hidden" name="csrf_token"
                        value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="item_id" id="modalItemId" value="">
                    <button type="submit" name="add_to_cart" class="btn btn-cart">Add To Cart</button>
                </form>

                <button id="modalOutOfStockBtn" class="btn out-of-stock"
                    style="display:none; background-color: #f0f0f0; cursor: not-allowed; width: 100%;" readonly>Out Of
                    Stock</button>
            </div>
        </div>
    </div>

    <?php include __DIR__ . '/templates/footer.php'; ?>

    <script src="<?php echo htmlspecialchars(BASE_URL, ENT_QUOTES, 'UTF-8'); ?>/javascripts/script.js"></script>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            // UI: Admin Toggle Logic (Switches visibility of admin-specific elements)
            const adminToggle = document.getElementById('adminToggle');
            const adminElements = document.querySelectorAll('.admin-element');

            if (adminToggle) {
                adminToggle.addEventListener('change', function () {
                    const isChecked = this.checked;
                    adminElements.forEach(element => {
                        element.style.display = isChecked ? '' : 'none';
                    });
                });
            }

            // UI: Learn More Modal Logic
            const modal = document.getElementById("learnMoreModal");
            const closeBtn = document.querySelector(".close-btn");
            const learnMoreBtns = document.querySelectorAll(".btn-learn-more");

            // UI: Modal Element References
            const modalTitle = document.getElementById("modalTitle");
            const modalImage = document.getElementById("modalImage");
            const modalPrice = document.getElementById("modalPrice");
            const modalStock = document.getElementById("modalStock");
            const modalDesc = document.getElementById("modalDesc");
            const modalSpecs = document.getElementById("modalSpecs");

            const modalForm = document.getElementById("modalForm");
            const modalItemId = document.getElementById("modalItemId");
            const modalOutOfStockBtn = document.getElementById("modalOutOfStockBtn");

            // LOGIC: Populate and open modal when a "Learn More" button is clicked
            learnMoreBtns.forEach(btn => {
                btn.addEventListener("click", function () {
                    // INPUT: Populate modal fields from data attributes
                    modalTitle.textContent = this.dataset.name;
                    modalImage.src = this.dataset.image;
                    modalPrice.textContent = "$" + this.dataset.price;
                    modalStock.textContent = "In Stock: " + this.dataset.stock;
                    modalDesc.textContent = this.dataset.desc;
                    modalSpecs.textContent = this.dataset.specs;

                    const stock = parseInt(this.dataset.stock);
                    const itemId = this.dataset.id;

                    modalItemId.value = itemId;

                    // LOGIC: Toggle between Add to Cart and Out of Stock buttons based on quantity
                    if (stock > 0) {
                        modalForm.style.display = "block";
                        modalOutOfStockBtn.style.display = "none";
                    } else {
                        modalForm.style.display = "none";
                        modalOutOfStockBtn.style.display = "block";
                    }

                    modal.style.display = "block";
                });
            });

            // UI: Close modal on X button click
            closeBtn.onclick = function () {
                modal.style.display = "none";
            }

            // UI: Close modal when clicking outside of it
            window.onclick = function (event) {
                if (event.target == modal) {
                    modal.style.display = "none";
                }
            }
        });
    </script>
</body>

</html>
<?php $conn->close(); ?>